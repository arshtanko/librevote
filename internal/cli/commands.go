package cli

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"librevote/internal/app"
	"librevote/internal/discovery"
	"librevote/internal/domain"
	"librevote/internal/frontend"
	"librevote/internal/sync"
	"librevote/internal/transport"
	"librevote/internal/validation"
)

func parseFlags(args []string, known map[string]struct{}) (map[string]string, error) {
	flags := map[string]string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") {
			return nil, fmt.Errorf("unexpected positional argument %q", arg)
		}
		key := arg[2:]
		if key == "" {
			return nil, errors.New("empty flag name")
		}
		if _, ok := known[key]; !ok {
			return nil, fmt.Errorf("unknown flag --%s", key)
		}
		if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
			return nil, fmt.Errorf("flag --%s requires a value", key)
		}
		flags[key] = args[i+1]
		i++
	}
	return flags, nil
}

func cmdInit(args []string, stdout, stderr io.Writer) int {
	flags, err := parseFlags(args, initKnownFlags)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	dataDir := flags["db"]
	networkID := flags["network"]
	if dataDir == "" || networkID == "" {
		fmt.Fprintln(stderr, "error: --db and --network are required")
		return 2
	}
	svc, err := app.Open(dataDir, networkID)
	if err != nil {
		fmt.Fprintf(stderr, "error: init failed: %v\n", err)
		return 1
	}
	if err := svc.Close(); err != nil {
		fmt.Fprintf(stderr, "error: close failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "initialized database at %s for network %s\n", dataDir, networkID)
	return 0
}

func cmdTrusteeElection(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "error: trustee-election requires a subcommand: create")
		return 2
	}
	switch args[0] {
	case "create":
		return cmdTrusteeElectionCreate(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "error: unknown trustee-election subcommand %q\n", args[0])
		return 2
	}
}

func cmdTrusteeElectionCreate(args []string, stdout, stderr io.Writer) int {
	flags, err := parseFlags(args, trusteeElectionCreateKnownFlags)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	dataDir := flags["db"]
	selectionID := flags["id"]
	title := flags["title"]
	if dataDir == "" || selectionID == "" || title == "" {
		fmt.Fprintln(stderr, "error: --db, --id, and --title are required")
		return 2
	}
	networkID := flags["network"]
	if networkID == "" {
		stored, err := app.ReadNetworkID(dataDir)
		if err != nil {
			fmt.Fprintf(stderr, "error: --network is required (could not read stored network: %v)\n", err)
			return 2
		}
		networkID = stored
	}

	svc, err := app.Open(dataDir, networkID)
	if err != nil {
		fmt.Fprintf(stderr, "error: open failed: %v\n", err)
		return 1
	}
	defer svc.Close()

	ctx := context.Background()

	voterNames := []string{"voter-1", "voter-2", "voter-3"}
	voters := make([]domain.VoterEntry, len(voterNames))
	for i, name := range voterNames {
		voters[i] = domain.VoterEntry{
			VoterID:                  name,
			VoterSigningPublicKey:    demoEd25519PubFromName(name),
			VoterEncryptionPublicKey: demoEncryptionKeyFromName(name),
		}
	}

	creatorPriv := demoEd25519PrivFromName("creator")
	payload := domain.TrusteeSelectionElectionPayload{
		TrusteeSelectionID: selectionID,
		NetworkID:          networkID,
		Title:              title,
		Description:        "MVP trustee selection election",
		VoterAllowlist:     voters,
		NominationStartsAt: 1000,
		NominationEndsAt:   2000,
		VotingStartsAt:     3000,
		VotingEndsAt:       4000,
		ConsentStartsAt:    5000,
		ConsentEndsAt:      6000,
		TrusteeCountN:      domain.TrusteeCountV1,
		ThresholdT:         domain.ThresholdV1,
		MaxChoicesPerVote:  domain.MaxChoicesPerVoteV1,
	}

	envelope, err := svc.CreateTrusteeSelectionElection(ctx, payload, creatorPriv, 500)
	if err != nil {
		fmt.Fprintf(stderr, "error: create trustee election failed: %v\n", err)
		return 5
	}

	fmt.Fprintf(stdout, "created %s\n", envelope.ObjectID)
	fmt.Fprintf(stdout, "  type: %s\n", envelope.ObjectType)
	fmt.Fprintf(stdout, "  scope: %s\n", envelope.Scope)
	status, _, err := svc.ValidationStatus(ctx, envelope.ObjectID)
	if err != nil {
		fmt.Fprintf(stderr, "error: check status failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "  status: %s\n", status)
	fmt.Fprintf(stdout, "  selection_id: %s\n", selectionID)
	fmt.Fprintf(stdout, "  voters: %d\n", len(voters))
	fmt.Fprintf(stdout, "  allowed voter labels: %s\n", strings.Join(voterNames, ", "))
	return 0
}

func cmdTrustee(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "error: trustee requires a subcommand: nominate, vote, result, consent")
		return 2
	}
	switch args[0] {
	case "nominate":
		return cmdTrusteeNominate(args[1:], stdout, stderr)
	case "vote":
		return cmdTrusteeVote(args[1:], stdout, stderr)
	case "result":
		return cmdTrusteeResult(args[1:], stdout, stderr)
	case "consent":
		return cmdTrusteeConsent(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "error: unknown trustee subcommand %q\n", args[0])
		return 2
	}
}

func cmdTrusteeNominate(args []string, stdout, stderr io.Writer) int {
	flags, err := parseFlags(args, trusteeNominateKnownFlags)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	dataDir := flags["db"]
	selectionID := flags["selection"]
	name := flags["name"]
	if dataDir == "" || selectionID == "" || name == "" {
		fmt.Fprintln(stderr, "error: --db, --selection, and --name are required")
		return 2
	}
	networkID := flags["network"]
	if networkID == "" {
		stored, err := app.ReadNetworkID(dataDir)
		if err != nil {
			fmt.Fprintf(stderr, "error: --network is required (could not read stored network: %v)\n", err)
			return 2
		}
		networkID = stored
	}

	svc, err := app.Open(dataDir, networkID)
	if err != nil {
		fmt.Fprintf(stderr, "error: open failed: %v\n", err)
		return 1
	}
	defer svc.Close()

	ctx := context.Background()

	candidatePriv := demoEd25519PrivFromName(name)
	candidatePub := demoEd25519PubFromName(name)
	blindKey := demoBlindKeyFromName(name)

	payload := domain.TrusteeNominationPayload{
		TrusteeSelectionID:           selectionID,
		CandidatePublicKey:           candidatePub,
		CandidateBlindTokenPublicKey: blindKey,
		CandidateNodePeerID:          "demo-peer",
		Statement:                    "Candidate " + name,
	}

	envelope, err := svc.CreateTrusteeNomination(ctx, payload, candidatePriv, 1500)
	if err != nil {
		fmt.Fprintf(stderr, "error: create nomination failed: %v\n", err)
		return 5
	}

	fmt.Fprintf(stdout, "created %s\n", envelope.ObjectID)
	fmt.Fprintf(stdout, "  type: %s\n", envelope.ObjectType)
	fmt.Fprintf(stdout, "  candidate: %s\n", name)
	status, _, err := svc.ValidationStatus(ctx, envelope.ObjectID)
	if err != nil {
		fmt.Fprintf(stderr, "error: check status failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "  status: %s\n", status)
	return 0
}

func cmdTrusteeVote(args []string, stdout, stderr io.Writer) int {
	flags, err := parseFlags(args, trusteeVoteKnownFlags)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	dataDir := flags["db"]
	selectionID := flags["selection"]
	voterName := normalizeVoterLabel(flags["voter"])
	candidatesRaw := flags["candidates"]
	if dataDir == "" || selectionID == "" || voterName == "" || candidatesRaw == "" {
		fmt.Fprintln(stderr, "error: --db, --selection, --voter, and --candidates are required")
		return 2
	}
	networkID := flags["network"]
	if networkID == "" {
		stored, err := app.ReadNetworkID(dataDir)
		if err != nil {
			fmt.Fprintf(stderr, "error: --network is required (could not read stored network: %v)\n", err)
			return 2
		}
		networkID = stored
	}

	candidateNames := strings.Split(candidatesRaw, ",")
	if len(candidateNames) == 0 {
		fmt.Fprintln(stderr, "error: --candidates must contain at least one name")
		return 2
	}

	svc, err := app.Open(dataDir, networkID)
	if err != nil {
		fmt.Fprintf(stderr, "error: open failed: %v\n", err)
		return 1
	}
	defer svc.Close()

	ctx := context.Background()

	voterPriv := demoEd25519PrivFromName(voterName)
	voterPub := demoEd25519PubFromName(voterName)

	candidateKeys := make([][]byte, len(candidateNames))
	for i, name := range candidateNames {
		candidateKeys[i] = demoEd25519PubFromName(strings.TrimSpace(name))
	}

	payload := domain.TrusteeVotePayload{
		TrusteeSelectionID:    selectionID,
		VoterPublicKey:        voterPub,
		SelectedCandidateKeys: candidateKeys,
	}

	envelope, err := svc.CreateTrusteeVote(ctx, payload, voterPriv, 3500)
	if err != nil {
		fmt.Fprintf(stderr, "error: create vote failed: %v\n", err)
		return 5
	}

	fmt.Fprintf(stdout, "created %s\n", envelope.ObjectID)
	fmt.Fprintf(stdout, "  type: %s\n", envelope.ObjectType)
	fmt.Fprintf(stdout, "  voter: %s\n", voterName)
	fmt.Fprintf(stdout, "  candidates: %s\n", candidatesRaw)
	status, _, err := svc.ValidationStatus(ctx, envelope.ObjectID)
	if err != nil {
		fmt.Fprintf(stderr, "error: check status failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "  status: %s\n", status)
	return 0
}

func cmdTrusteeResult(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "error: trustee result requires a subcommand: build")
		return 2
	}
	switch args[0] {
	case "build":
		return cmdTrusteeResultBuild(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "error: unknown trustee result subcommand %q\n", args[0])
		return 2
	}
}

func cmdTrusteeResultBuild(args []string, stdout, stderr io.Writer) int {
	flags, err := parseFlags(args, trusteeResultBuildKnownFlags)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	dataDir := flags["db"]
	selectionID := flags["selection"]
	if dataDir == "" || selectionID == "" {
		fmt.Fprintln(stderr, "error: --db and --selection are required")
		return 2
	}
	networkID := flags["network"]
	if networkID == "" {
		stored, err := app.ReadNetworkID(dataDir)
		if err != nil {
			fmt.Fprintf(stderr, "error: --network is required (could not read stored network: %v)\n", err)
			return 2
		}
		networkID = stored
	}

	svc, err := app.Open(dataDir, networkID)
	if err != nil {
		fmt.Fprintf(stderr, "error: open failed: %v\n", err)
		return 1
	}
	defer svc.Close()

	ctx := context.Background()

	reporterPub := demoEd25519PubFromName("reporter")
	reporterPriv := demoEd25519PrivFromName("reporter")

	envelope, err := svc.BuildTrusteeSelectionResult(ctx, selectionID, reporterPub, reporterPriv)
	if err != nil {
		fmt.Fprintf(stderr, "error: build result failed: %v\n", err)
		return 5
	}

	fmt.Fprintf(stdout, "created %s\n", envelope.ObjectID)
	fmt.Fprintf(stdout, "  type: %s\n", envelope.ObjectType)
	fmt.Fprintf(stdout, "  selection_id: %s\n", selectionID)
	status, _, err := svc.ValidationStatus(ctx, envelope.ObjectID)
	if err != nil {
		fmt.Fprintf(stderr, "error: check status failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "  status: %s\n", status)
	return 0
}

func cmdTrusteeConsent(args []string, stdout, stderr io.Writer) int {
	flags, err := parseFlags(args, trusteeConsentKnownFlags)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	dataDir := flags["db"]
	name := flags["name"]
	electionID := flags["election"]
	if dataDir == "" || name == "" || electionID == "" {
		fmt.Fprintln(stderr, "error: --db, --name, and --election are required")
		return 2
	}
	networkID := flags["network"]
	if networkID == "" {
		stored, err := app.ReadNetworkID(dataDir)
		if err != nil {
			fmt.Fprintf(stderr, "error: --network is required (could not read stored network: %v)\n", err)
			return 2
		}
		networkID = stored
	}

	svc, err := app.Open(dataDir, networkID)
	if err != nil {
		fmt.Fprintf(stderr, "error: open failed: %v\n", err)
		return 1
	}
	defer svc.Close()

	ctx := context.Background()

	electionPayload, err := svc.LoadAnonymousElection(ctx, electionID)
	if err != nil {
		fmt.Fprintf(stderr, "error: load election: %v\n", err)
		return 5
	}

	trusteePriv := demoEd25519PrivFromName(name)
	trusteePub := demoEd25519PubFromName(name)
	tallySetupKey := demoTallySetupKeyFromName(name)

	payload := domain.TrusteeConsentPayload{
		TrusteeSelectionID:         electionPayload.TrusteeSelectionID,
		TrusteeSelectionResultHash: electionPayload.TrusteeSelectionResultHash,
		ElectionID:                 electionID,
		ElectionParametersHash:     validation.ComputeElectionParametersHash(electionPayload),
		TrusteePublicKey:           trusteePub,
		TrusteeTallySetupPublicKey: tallySetupKey,
		ThresholdT:                 domain.ThresholdV1,
		TrusteeCountN:              domain.TrusteeCountV1,
	}

	envelope, err := svc.CreateTrusteeConsent(ctx, payload, trusteePriv, 5500)
	if err != nil {
		fmt.Fprintf(stderr, "error: create trustee consent failed: %v\n", err)
		return 5
	}

	fmt.Fprintf(stdout, "created %s\n", envelope.ObjectID)
	fmt.Fprintf(stdout, "  type: %s\n", envelope.ObjectType)
	fmt.Fprintf(stdout, "  trustee: %s\n", name)
	fmt.Fprintf(stdout, "  election: %s\n", electionID)
	status, _, err := svc.ValidationStatus(ctx, envelope.ObjectID)
	if err != nil {
		fmt.Fprintf(stderr, "error: check status failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "  status: %s\n", status)
	return 0
}

func cmdElection(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "error: election requires a subcommand: create")
		return 2
	}
	switch args[0] {
	case "create":
		return cmdElectionCreate(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "error: unknown election subcommand %q\n", args[0])
		return 2
	}
}

func cmdElectionCreate(args []string, stdout, stderr io.Writer) int {
	flags, err := parseFlags(args, electionCreateKnownFlags)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	dataDir := flags["db"]
	electionID := flags["id"]
	title := flags["title"]
	selectionID := flags["selection"]
	if dataDir == "" || electionID == "" || title == "" || selectionID == "" {
		fmt.Fprintln(stderr, "error: --db, --id, --title, and --selection are required")
		return 2
	}
	networkID := flags["network"]
	if networkID == "" {
		stored, err := app.ReadNetworkID(dataDir)
		if err != nil {
			fmt.Fprintf(stderr, "error: --network is required (could not read stored network: %v)\n", err)
			return 2
		}
		networkID = stored
	}

	optionsStr := flags["options"]
	options := []string{"yes", "no"}
	if optionsStr != "" {
		options = strings.Split(optionsStr, ",")
		for i := range options {
			options[i] = strings.TrimSpace(options[i])
		}
	}

	svc, err := app.Open(dataDir, networkID)
	if err != nil {
		fmt.Fprintf(stderr, "error: open failed: %v\n", err)
		return 1
	}
	defer svc.Close()

	ctx := context.Background()

	voterNames := []string{"voter-1", "voter-2", "voter-3"}
	voters := make([]domain.VoterEntry, len(voterNames))
	for i, name := range voterNames {
		voters[i] = domain.VoterEntry{
			VoterID:                  name,
			VoterSigningPublicKey:    demoEd25519PubFromName(name),
			VoterEncryptionPublicKey: demoEncryptionKeyFromName(name),
		}
	}

	creatorPriv := demoEd25519PrivFromName("creator")

	resultHash, err := svc.TrusteeSelectionResultHash(ctx, selectionID)
	if err != nil {
		fmt.Fprintf(stderr, "error: cannot find trustee selection result for %s: %v\n", selectionID, err)
		return 5
	}

	payload := domain.AnonymousElectionPayload{
		ElectionID:                 electionID,
		NetworkID:                  networkID,
		Title:                      title,
		Description:                "MVP anonymous election",
		Options:                    options,
		VoterAllowlist:             voters,
		TrusteeSelectionID:         selectionID,
		TrusteeSelectionResultHash: resultHash,
		ThresholdT:                 domain.ThresholdV1,
		TrusteeCountN:              domain.TrusteeCountV1,
		EligibilityScheme:          domain.EligibilitySchemeBlindTokenV1,
		IssuanceStartsAt:           7000,
		IssuanceEndsAt:             8000,
		VotingStartsAt:             9000,
		VotingEndsAt:               10000,
		TallyStartsAt:              11000,
	}

	envelope, err := svc.CreateAnonymousElection(ctx, payload, creatorPriv, 6000)
	if err != nil {
		fmt.Fprintf(stderr, "error: create election failed: %v\n", err)
		return 5
	}

	fmt.Fprintf(stdout, "created %s\n", envelope.ObjectID)
	fmt.Fprintf(stdout, "  type: %s\n", envelope.ObjectType)
	fmt.Fprintf(stdout, "  title: %s\n", title)
	fmt.Fprintf(stdout, "  election_id: %s\n", electionID)
	fmt.Fprintf(stdout, "  selection_id: %s\n", selectionID)
	fmt.Fprintf(stdout, "  options: %s\n", strings.Join(options, ", "))
	status, _, err := svc.ValidationStatus(ctx, envelope.ObjectID)
	if err != nil {
		fmt.Fprintf(stderr, "error: check status failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "  status: %s\n", status)
	return 0
}

func cmdTallyKey(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "error: tally-key requires a subcommand: contribute, build")
		return 2
	}
	switch args[0] {
	case "contribute":
		return cmdTallyKeyContribute(args[1:], stdout, stderr)
	case "build":
		return cmdTallyKeyBuild(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "error: unknown tally-key subcommand %q\n", args[0])
		return 2
	}
}

func cmdTallyKeyContribute(args []string, stdout, stderr io.Writer) int {
	flags, err := parseFlags(args, tallyKeyContributeKnownFlags)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	dataDir := flags["db"]
	electionID := flags["election"]
	name := flags["name"]
	if dataDir == "" || electionID == "" || name == "" {
		fmt.Fprintln(stderr, "error: --db, --election, and --name are required")
		return 2
	}
	networkID := flags["network"]
	if networkID == "" {
		stored, err := app.ReadNetworkID(dataDir)
		if err != nil {
			fmt.Fprintf(stderr, "error: --network is required (could not read stored network: %v)\n", err)
			return 2
		}
		networkID = stored
	}

	svc, err := app.Open(dataDir, networkID)
	if err != nil {
		fmt.Fprintf(stderr, "error: open failed: %v\n", err)
		return 1
	}
	defer svc.Close()

	ctx := context.Background()

	finalTrustees, err := svc.FinalTrusteeSet(ctx, electionID)
	if err != nil {
		fmt.Fprintf(stderr, "error: final trustee set: %v\n", err)
		return 5
	}

	trusteePriv := demoEd25519PrivFromName(name)
	trusteePub := demoEd25519PubFromName(name)
	tallySetupKey := demoTallySetupKeyFromName(name)

	envelope, err := svc.CreateTallyKeyContribution(ctx, electionID, trusteePub, tallySetupKey, finalTrustees, trusteePriv, 8000)
	if err != nil {
		fmt.Fprintf(stderr, "error: create tally key contribution failed: %v\n", err)
		return 5
	}

	fmt.Fprintf(stdout, "created %s\n", envelope.ObjectID)
	fmt.Fprintf(stdout, "  type: %s\n", envelope.ObjectType)
	fmt.Fprintf(stdout, "  trustee: %s\n", name)
	fmt.Fprintf(stdout, "  election: %s\n", electionID)
	status, _, err := svc.ValidationStatus(ctx, envelope.ObjectID)
	if err != nil {
		fmt.Fprintf(stderr, "error: check status failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "  status: %s\n", status)
	return 0
}

func cmdTallyKeyBuild(args []string, stdout, stderr io.Writer) int {
	flags, err := parseFlags(args, tallyKeyBuildKnownFlags)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	dataDir := flags["db"]
	electionID := flags["election"]
	if dataDir == "" || electionID == "" {
		fmt.Fprintln(stderr, "error: --db and --election are required")
		return 2
	}
	networkID := flags["network"]
	if networkID == "" {
		stored, err := app.ReadNetworkID(dataDir)
		if err != nil {
			fmt.Fprintf(stderr, "error: --network is required (could not read stored network: %v)\n", err)
			return 2
		}
		networkID = stored
	}

	svc, err := app.Open(dataDir, networkID)
	if err != nil {
		fmt.Fprintf(stderr, "error: open failed: %v\n", err)
		return 1
	}
	defer svc.Close()

	ctx := context.Background()

	reporterPub := demoEd25519PubFromName("reporter")
	reporterPriv := demoEd25519PrivFromName("reporter")

	envelope, err := svc.BuildTallyKeySet(ctx, electionID, reporterPub, reporterPriv)
	if err != nil {
		fmt.Fprintf(stderr, "error: build tally key set failed: %v\n", err)
		return 5
	}

	fmt.Fprintf(stdout, "created %s\n", envelope.ObjectID)
	fmt.Fprintf(stdout, "  type: %s\n", envelope.ObjectType)
	fmt.Fprintf(stdout, "  election_id: %s\n", electionID)
	status, _, err := svc.ValidationStatus(ctx, envelope.ObjectID)
	if err != nil {
		fmt.Fprintf(stderr, "error: check status failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "  status: %s\n", status)
	return 0
}

func cmdBallot(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "error: ballot requires a subcommand: cast")
		return 2
	}
	switch args[0] {
	case "cast":
		return cmdBallotCast(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "error: unknown ballot subcommand %q\n", args[0])
		return 2
	}
}

func cmdBallotCast(args []string, stdout, stderr io.Writer) int {
	flags, err := parseFlags(args, ballotCastKnownFlags)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	dataDir := flags["db"]
	electionID := flags["election"]
	voterLabel := normalizeVoterLabel(flags["voter"])
	choice := flags["choice"]
	if dataDir == "" || electionID == "" || voterLabel == "" || choice == "" {
		fmt.Fprintln(stderr, "error: --db, --election, --voter, and --choice are required")
		return 2
	}
	networkID := flags["network"]
	if networkID == "" {
		stored, err := app.ReadNetworkID(dataDir)
		if err != nil {
			fmt.Fprintf(stderr, "error: --network is required (could not read stored network: %v)\n", err)
			return 2
		}
		networkID = stored
	}

	svc, err := app.Open(dataDir, networkID)
	if err != nil {
		fmt.Fprintf(stderr, "error: open failed: %v\n", err)
		return 1
	}
	defer svc.Close()

	ctx := context.Background()

	voterPriv := demoEd25519PrivFromName(voterLabel)

	envelope, err := svc.CastBallot(ctx, electionID, voterLabel, choice, voterPriv, 9500)
	if err != nil {
		fmt.Fprintf(stderr, "error: cast ballot failed: %v\n", err)
		return 5
	}

	fmt.Fprintf(stdout, "created %s\n", envelope.ObjectID)
	fmt.Fprintf(stdout, "  type: %s\n", envelope.ObjectType)
	fmt.Fprintf(stdout, "  election: %s\n", electionID)
	fmt.Fprintf(stdout, "  voter: %s\n", voterLabel)
	fmt.Fprintf(stdout, "  choice: %s\n", choice)
	status, _, err := svc.ValidationStatus(ctx, envelope.ObjectID)
	if err != nil {
		fmt.Fprintf(stderr, "error: check status failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "  status: %s\n", status)
	return 0
}

func cmdTally(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "error: tally requires a subcommand: build, show")
		return 2
	}
	switch args[0] {
	case "build":
		return cmdTallyBuild(args[1:], stdout, stderr)
	case "show":
		return cmdTallyShow(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "error: unknown tally subcommand %q\n", args[0])
		return 2
	}
}

func cmdTallyBuild(args []string, stdout, stderr io.Writer) int {
	flags, err := parseFlags(args, tallyBuildKnownFlags)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	dataDir := flags["db"]
	electionID := flags["election"]
	if dataDir == "" || electionID == "" {
		fmt.Fprintln(stderr, "error: --db and --election are required")
		return 2
	}
	networkID := flags["network"]
	if networkID == "" {
		stored, err := app.ReadNetworkID(dataDir)
		if err != nil {
			fmt.Fprintf(stderr, "error: --network is required (could not read stored network: %v)\n", err)
			return 2
		}
		networkID = stored
	}

	svc, err := app.Open(dataDir, networkID)
	if err != nil {
		fmt.Fprintf(stderr, "error: open failed: %v\n", err)
		return 1
	}
	defer svc.Close()

	ctx := context.Background()

	reporterPub := demoEd25519PubFromName("reporter")
	reporterPriv := demoEd25519PrivFromName("reporter")

	envelope, err := svc.BuildTallyResult(ctx, electionID, reporterPub, reporterPriv, 12000)
	if err != nil {
		fmt.Fprintf(stderr, "error: build tally result failed: %v\n", err)
		return 5
	}

	fmt.Fprintf(stdout, "created %s\n", envelope.ObjectID)
	fmt.Fprintf(stdout, "  type: %s\n", envelope.ObjectType)
	fmt.Fprintf(stdout, "  election: %s\n", electionID)
	status, _, err := svc.ValidationStatus(ctx, envelope.ObjectID)
	if err != nil {
		fmt.Fprintf(stderr, "error: check status failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "  status: %s\n", status)
	return 0
}

func cmdTallyShow(args []string, stdout, stderr io.Writer) int {
	flags, err := parseFlags(args, tallyShowKnownFlags)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	dataDir := flags["db"]
	electionID := flags["election"]
	if dataDir == "" || electionID == "" {
		fmt.Fprintln(stderr, "error: --db and --election are required")
		return 2
	}
	networkID := flags["network"]
	if networkID == "" {
		stored, err := app.ReadNetworkID(dataDir)
		if err != nil {
			fmt.Fprintf(stderr, "error: --network is required (could not read stored network: %v)\n", err)
			return 2
		}
		networkID = stored
	}

	svc, err := app.Open(dataDir, networkID)
	if err != nil {
		fmt.Fprintf(stderr, "error: open failed: %v\n", err)
		return 1
	}
	defer svc.Close()

	ctx := context.Background()

	inputs, err := svc.GetTallyComputationInputs(ctx, electionID)
	if err != nil {
		fmt.Fprintf(stderr, "error: load tally inputs: %v\n", err)
		return 5
	}
	if !inputs.ElectionFound {
		fmt.Fprintln(stderr, "error: election not found")
		return 7
	}
	if !inputs.TallyKeySetFound {
		fmt.Fprintln(stderr, "error: no valid TallyKeySet - tally not available")
		return 7
	}

	computed := validation.ComputeLocalTallyResultForService(electionID, inputs.TallyKeySetHash, inputs.RetainedBallots, inputs.Election.Options)
	fmt.Fprintf(stdout, "tally for election %s\n", electionID)
	fmt.Fprintf(stdout, "  valid_ballot_count: %d\n", computed.ValidBallotCount)
	fmt.Fprintf(stdout, "  conflicted_ballot_count: %d\n", computed.ConflictedBallotCount)
	fmt.Fprintf(stdout, "  option_results:\n")
	for _, r := range computed.OptionResults {
		fmt.Fprintf(stdout, "    %s: %d\n", r.Option, r.Count)
	}
	return 0
}

func placeholderHash(tag, seed string) []byte {
	h := sha256.New()
	h.Write([]byte(tag))
	h.Write([]byte(seed))
	return h.Sum(nil)
}

func cmdNode(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "error: node requires a subcommand: sync, serve, discover, start")
		return 2
	}
	switch args[0] {
	case "sync":
		return cmdNodeSync(args[1:], stdout, stderr)
	case "serve":
		return cmdNodeServe(args[1:], stdout, stderr)
	case "discover":
		return cmdNodeDiscover(args[1:], stdout, stderr)
	case "start":
		return cmdNodeStart(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "error: unknown node subcommand %q\n", args[0])
		return 2
	}
}

func cmdNodeSync(args []string, stdout, stderr io.Writer) int {
	flags, err := parseFlags(args, nodeSyncKnownFlags)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	dataDir := flags["db"]
	peerURLs := flags["peer"]
	if dataDir == "" || peerURLs == "" {
		fmt.Fprintln(stderr, "error: --db and --peer are required")
		return 2
	}
	scope := flags["scope"]
	if scope == "" {
		scope = string(domain.ScopeNetwork)
	}
	scopeID := flags["scope-id"]
	if domain.ScopeIDRequired(domain.Scope(scope)) {
		if scopeID == "" {
			fmt.Fprintf(stderr, "error: scope %q requires --scope-id\n", scope)
			return 2
		}
	} else {
		if scopeID != "" {
			fmt.Fprintf(stderr, "error: scope %q requires empty --scope-id\n", scope)
			return 2
		}
	}

	networkID := flags["network"]
	if networkID == "" {
		stored, err := app.ReadNetworkID(dataDir)
		if err != nil {
			fmt.Fprintf(stderr, "error: --network is required (could not read stored network: %v)\n", err)
			return 2
		}
		networkID = stored
	}

	svc, err := app.Open(dataDir, networkID)
	if err != nil {
		fmt.Fprintf(stderr, "error: open failed: %v\n", err)
		return 1
	}
	defer svc.Close()

	peers := strings.Split(peerURLs, ",")
	for i := range peers {
		peers[i] = strings.TrimSpace(peers[i])
	}

	ctx := context.Background()
	httpTransport := transport.NewHTTPTransport()

	result, err := sync.Sync(ctx, httpTransport, svc, svc, scope, scopeID, nil, peers)
	if err != nil {
		fmt.Fprintf(stderr, "sync error: %v\n", err)
	}

	fmt.Fprintf(stdout, "sync complete\n")
	fmt.Fprintf(stdout, "  scope: %s\n", scope)
	if scopeID != "" {
		fmt.Fprintf(stdout, "  scope_id: %s\n", scopeID)
	}
	fmt.Fprintf(stdout, "  fetched: %d\n", result.Fetched)
	fmt.Fprintf(stdout, "  ingested: %d\n", result.Ingested)
	if len(result.Errors) > 0 {
		fmt.Fprintf(stdout, "  errors: %d\n", len(result.Errors))
		for _, e := range result.Errors {
			fmt.Fprintf(stdout, "    - %s\n", e)
		}
	}
	if err != nil {
		return 6
	}
	return 0
}

func cmdNodeServe(args []string, stdout, stderr io.Writer) int {
	flags, err := parseFlags(args, nodeServeKnownFlags)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	dataDir := flags["db"]
	listenAddr := flags["listen"]
	if dataDir == "" {
		fmt.Fprintln(stderr, "error: --db is required")
		return 2
	}
	if listenAddr == "" {
		listenAddr = ":8080"
	}

	networkID := flags["network"]
	if networkID == "" {
		stored, err := app.ReadNetworkID(dataDir)
		if err != nil {
			fmt.Fprintf(stderr, "error: --network is required (could not read stored network: %v)\n", err)
			return 2
		}
		networkID = stored
	}

	svc, err := app.Open(dataDir, networkID)
	if err != nil {
		fmt.Fprintf(stderr, "error: open failed: %v\n", err)
		return 1
	}
	defer svc.Close()

	server := transport.NewServer(svc, networkID)
	httpServer := &http.Server{
		Addr:    listenAddr,
		Handler: server.Handler(),
	}

	fmt.Fprintf(stdout, "serving on %s (network: %s)\n", listenAddr, networkID)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh
		httpServer.Shutdown(context.Background())
	}()

	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(stderr, "error: serve failed: %v\n", err)
		return 1
	}

	fmt.Fprintln(stdout, "server stopped")
	return 0
}

func cmdNodeDiscover(args []string, stdout, stderr io.Writer) int {
	flags, err := parseFlags(args, nodeDiscoverKnownFlags)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	dataDir := flags["db"]
	if dataDir == "" {
		fmt.Fprintln(stderr, "error: --db is required")
		return 2
	}

	networkID := flags["network"]
	if networkID == "" {
		stored, err := app.ReadNetworkID(dataDir)
		if err != nil {
			fmt.Fprintf(stderr, "error: --network is required (could not read stored network: %v)\n", err)
			return 2
		}
		networkID = stored
	}

	bootstrapRaw := flags["bootstrap"]
	var bootstrapPeers []string
	if bootstrapRaw != "" {
		for _, p := range strings.Split(bootstrapRaw, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				bootstrapPeers = append(bootstrapPeers, p)
			}
		}
	}

	keyPath := flags["key"]
	if keyPath == "" {
		keyPath = dataDir + "/node_discovery.key"
	}

	listenRaw := flags["listen"]
	var listenAddrs []string
	if listenRaw != "" {
		listenAddrs = strings.Split(listenRaw, ",")
		for i := range listenAddrs {
			listenAddrs[i] = strings.TrimSpace(listenAddrs[i])
		}
	}

	rendezvousPrefix := flags["rendezvous"]
	if rendezvousPrefix == "" {
		rendezvousPrefix = "/librevote"
	}

	mode := flags["mode"]
	if mode == "" {
		mode = "auto"
	}
	switch mode {
	case "auto", "server", "client":
	default:
		fmt.Fprintf(stderr, "error: invalid --mode %q (valid: auto, server, client)\n", mode)
		return 2
	}

	httpAdvertise := flags["http-advertise"]

	config := discovery.Config{
		NetworkID:        networkID,
		BootstrapPeers:   bootstrapPeers,
		KeyPath:          keyPath,
		ListenAddrs:      listenAddrs,
		AdvertisedHTTP:   httpAdvertise,
		RendezvousPrefix: rendezvousPrefix,
		Mode:             mode,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	d, err := discovery.New(ctx, config)
	if err != nil {
		fmt.Fprintf(stderr, "error: create discovery: %v\n", err)
		if len(bootstrapPeers) > 0 {
			return 6
		}
		return 1
	}
	defer d.Close()

	peers, discoverErr := d.DiscoverPeers(ctx)

	fmt.Fprintf(stdout, "discovery on network %s\n", networkID)
	fmt.Fprintf(stdout, "  local_peer_id: %s\n", d.Identity().PeerID)
	fmt.Fprintf(stdout, "  namespace: %s\n", d.Namespace())
	fmt.Fprintf(stdout, "  mode: %s\n", d.Config().Mode)
	fmt.Fprintf(stdout, "  listen_addrs:\n")
	for _, a := range d.Host().Addrs() {
		fmt.Fprintf(stdout, "    - %s/p2p/%s\n", a, d.Identity().PeerID)
	}
	fmt.Fprintf(stdout, "  discovered_peers: %d\n", len(peers))

	for _, p := range peers {
		addrsStr := strings.Join(p.Addrs, ", ")
		if p.HTTPURL != "" {
			fmt.Fprintf(stdout, "    - %s addrs=[%s] http=%s\n", p.PeerID, addrsStr, p.HTTPURL)
		} else {
			fmt.Fprintf(stdout, "    - %s addrs=[%s]\n", p.PeerID, addrsStr)
		}
	}

	if discoverErr != nil {
		fmt.Fprintf(stderr, "warning: discovery errors: %v\n", discoverErr)
	}

	if len(bootstrapPeers) > 0 && len(peers) == 0 && discoverErr != nil {
		if !strings.Contains(discoverErr.Error(), "http url not") {
			return 6
		}
	}

	return 0
}

func cmdNodeStart(args []string, stdout, stderr io.Writer) int {
	flags, err := parseFlags(args, nodeStartKnownFlags)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	dataDir := flags["db"]
	if dataDir == "" {
		fmt.Fprintln(stderr, "error: --db is required")
		return 2
	}

	networkID := flags["network"]
	if networkID == "" {
		stored, err := app.ReadNetworkID(dataDir)
		if err != nil {
			fmt.Fprintf(stderr, "error: --network is required (could not read stored network: %v)\n", err)
			return 2
		}
		networkID = stored
	}

	listenHTTP := flags["listen-http"]
	if listenHTTP == "" {
		listenHTTP = "127.0.0.1:0"
	}

	var listenAddrs []string
	if raw := flags["listen-p2p"]; raw != "" {
		listenAddrs = strings.Split(raw, ",")
		for i := range listenAddrs {
			listenAddrs[i] = strings.TrimSpace(listenAddrs[i])
		}
	}

	keyPath := flags["key"]
	if keyPath == "" {
		keyPath = dataDir + "/node_start.key"
	}

	var bootstrapPeers []string
	if raw := flags["bootstrap"]; raw != "" {
		for _, p := range strings.Split(raw, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				bootstrapPeers = append(bootstrapPeers, p)
			}
		}
	}

	rendezvousPrefix := flags["rendezvous"]
	if rendezvousPrefix == "" {
		rendezvousPrefix = "/librevote"
	}

	mode := flags["mode"]
	if mode == "" {
		mode = "auto"
	}
	switch mode {
	case "auto", "server", "client":
	default:
		fmt.Fprintf(stderr, "error: invalid --mode %q (valid: auto, server, client)\n", mode)
		return 2
	}

	advertisedHTTP := flags["http-advertise"]

	announceInterval := 10 * time.Second
	if raw := flags["announce-interval"]; raw != "" {
		d, durErr := time.ParseDuration(raw)
		if durErr != nil {
			fmt.Fprintf(stderr, "error: invalid --announce-interval %q: %v\n", raw, durErr)
			return 2
		}
		if d <= 0 {
			fmt.Fprintf(stderr, "error: --announce-interval must be positive\n")
			return 2
		}
		announceInterval = d
	}

	config := app.NodeStartConfig{
		DataDir:          dataDir,
		NetworkID:        networkID,
		HTTPListenAddr:   listenHTTP,
		KeyPath:          keyPath,
		ListenAddrs:      listenAddrs,
		BootstrapPeers:   bootstrapPeers,
		RendezvousPrefix: rendezvousPrefix,
		Mode:             mode,
		AdvertisedHTTP:   advertisedHTTP,
		AnnounceInterval: announceInterval,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logf := func(format string, args ...interface{}) {
		fmt.Fprintf(stdout, format+"\n", args...)
	}

	ns, err := app.NewNodeStart(ctx, config, logf)
	if err != nil {
		fmt.Fprintf(stderr, "error: create node start: %v\n", err)
		return 1
	}

	if err := ns.Start(ctx); err != nil {
		ns.Stop()
		fmt.Fprintf(stderr, "error: start node: %v\n", err)
		return 6
	}

	fmt.Fprintf(stdout, "node started (network: %s)\n", networkID)
	fmt.Fprintf(stdout, "  http: %s\n", ns.Addr())

	if ns.Discovery() != nil {
		fmt.Fprintf(stdout, "  peer_id: %s\n", ns.Discovery().Identity().PeerID)
		fmt.Fprintf(stdout, "  namespace: %s\n", ns.Discovery().Namespace())
		fmt.Fprintf(stdout, "  mode: %s\n", ns.Discovery().Config().Mode)
		for _, a := range ns.Discovery().Host().Addrs() {
			fmt.Fprintf(stdout, "  listen: %s/p2p/%s\n", a, ns.Discovery().Identity().PeerID)
		}
	}

	fmt.Fprintf(stdout, "  network: %s\n", networkID)
	fmt.Fprintf(stdout, "  announce_interval: %s\n", announceInterval)

	if runErr := ns.Run(); runErr != nil {
		fmt.Fprintf(stderr, "error: node run: %v\n", runErr)
		return 1
	}
	return 0
}

func cmdFrontend(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "error: frontend requires a subcommand: serve")
		return 2
	}
	switch args[0] {
	case "serve":
		return cmdFrontendServe(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "error: unknown frontend subcommand %q\n", args[0])
		return 2
	}
}

func cmdFrontendServe(args []string, stdout, stderr io.Writer) int {
	flags, err := parseFlags(args, frontendServeKnownFlags)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	config, announceInterval, err := nodeStartConfigFromFlags(flags)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logf := func(format string, args ...interface{}) {
		fmt.Fprintf(stdout, format+"\n", args...)
	}

	ns, err := app.NewNodeStart(ctx, config, logf)
	if err != nil {
		fmt.Fprintf(stderr, "error: create frontend node: %v\n", err)
		return 1
	}
	ns.SetExtraHTTPHandler(frontend.NewServer(ns, ns.Service()).Handler())

	if err := ns.Start(ctx); err != nil {
		ns.Stop()
		fmt.Fprintf(stderr, "error: start frontend node: %v\n", err)
		return 6
	}

	fmt.Fprintf(stdout, "frontend node started (network: %s)\n", config.NetworkID)
	fmt.Fprintf(stdout, "  frontend: http://%s\n", ns.Addr())
	fmt.Fprintf(stdout, "  http: %s\n", ns.Addr())
	if ns.Discovery() != nil {
		fmt.Fprintf(stdout, "  peer_id: %s\n", ns.Discovery().Identity().PeerID)
		fmt.Fprintf(stdout, "  namespace: %s\n", ns.Discovery().Namespace())
		fmt.Fprintf(stdout, "  mode: %s\n", ns.Discovery().Config().Mode)
		for _, a := range ns.Discovery().Host().Addrs() {
			fmt.Fprintf(stdout, "  listen: %s/p2p/%s\n", a, ns.Discovery().Identity().PeerID)
		}
	}
	fmt.Fprintf(stdout, "  network: %s\n", config.NetworkID)
	fmt.Fprintf(stdout, "  announce_interval: %s\n", announceInterval)

	if runErr := ns.Run(); runErr != nil {
		fmt.Fprintf(stderr, "error: frontend run: %v\n", runErr)
		return 1
	}
	return 0
}

func nodeStartConfigFromFlags(flags map[string]string) (app.NodeStartConfig, time.Duration, error) {
	dataDir := flags["db"]
	if dataDir == "" {
		return app.NodeStartConfig{}, 0, fmt.Errorf("--db is required")
	}

	networkID := flags["network"]
	if networkID == "" {
		stored, err := app.ReadNetworkID(dataDir)
		if err != nil {
			return app.NodeStartConfig{}, 0, fmt.Errorf("--network is required (could not read stored network: %v)", err)
		}
		networkID = stored
	}

	listenHTTP := flags["listen-http"]
	if listenHTTP == "" {
		listenHTTP = "127.0.0.1:0"
	}

	var listenAddrs []string
	if raw := flags["listen-p2p"]; raw != "" {
		listenAddrs = strings.Split(raw, ",")
		for i := range listenAddrs {
			listenAddrs[i] = strings.TrimSpace(listenAddrs[i])
		}
	}

	keyPath := flags["key"]
	if keyPath == "" {
		keyPath = dataDir + "/node_start.key"
	}

	var bootstrapPeers []string
	if raw := flags["bootstrap"]; raw != "" {
		for _, p := range strings.Split(raw, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				bootstrapPeers = append(bootstrapPeers, p)
			}
		}
	}

	rendezvousPrefix := flags["rendezvous"]
	if rendezvousPrefix == "" {
		rendezvousPrefix = "/librevote"
	}

	mode := flags["mode"]
	if mode == "" {
		mode = "auto"
	}
	switch mode {
	case "auto", "server", "client":
	default:
		return app.NodeStartConfig{}, 0, fmt.Errorf("invalid --mode %q (valid: auto, server, client)", mode)
	}

	announceInterval := 10 * time.Second
	if raw := flags["announce-interval"]; raw != "" {
		d, durErr := time.ParseDuration(raw)
		if durErr != nil {
			return app.NodeStartConfig{}, 0, fmt.Errorf("invalid --announce-interval %q: %v", raw, durErr)
		}
		if d <= 0 {
			return app.NodeStartConfig{}, 0, fmt.Errorf("--announce-interval must be positive")
		}
		announceInterval = d
	}

	return app.NodeStartConfig{
		DataDir:          dataDir,
		NetworkID:        networkID,
		HTTPListenAddr:   listenHTTP,
		KeyPath:          keyPath,
		ListenAddrs:      listenAddrs,
		BootstrapPeers:   bootstrapPeers,
		RendezvousPrefix: rendezvousPrefix,
		Mode:             mode,
		AdvertisedHTTP:   flags["http-advertise"],
		AnnounceInterval: announceInterval,
	}, announceInterval, nil
}

var initKnownFlags = flagSet("db", "network")

var trusteeElectionCreateKnownFlags = flagSet("db", "id", "network", "title")

var trusteeNominateKnownFlags = flagSet("db", "selection", "name", "network")

var trusteeVoteKnownFlags = flagSet("db", "selection", "voter", "candidates", "network")

var trusteeResultBuildKnownFlags = flagSet("db", "selection", "network")

var trusteeConsentKnownFlags = flagSet("db", "name", "election", "network")

var electionCreateKnownFlags = flagSet("db", "id", "title", "selection", "options", "network")

var tallyKeyContributeKnownFlags = flagSet("db", "election", "name", "network")

var tallyKeyBuildKnownFlags = flagSet("db", "election", "network")

var ballotCastKnownFlags = flagSet("db", "election", "voter", "choice", "network")

var tallyBuildKnownFlags = flagSet("db", "election", "network")

var tallyShowKnownFlags = flagSet("db", "election", "network")

var nodeSyncKnownFlags = flagSet("db", "peer", "scope", "scope-id", "network")

var nodeServeKnownFlags = flagSet("db", "listen", "network")

var nodeDiscoverKnownFlags = flagSet("db", "bootstrap", "listen", "key", "network", "rendezvous", "mode", "http-advertise")

var nodeStartKnownFlags = flagSet("db", "listen-http", "listen-p2p", "key", "bootstrap", "http-advertise", "network", "rendezvous", "mode", "announce-interval")

var frontendServeKnownFlags = flagSet("db", "listen-http", "listen-p2p", "key", "bootstrap", "http-advertise", "network", "rendezvous", "mode", "announce-interval")

func flagSet(names ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(names))
	for _, n := range names {
		m[n] = struct{}{}
	}
	return m
}

var voterAliases = map[string]string{
	"voter1":  "voter-1",
	"voter2":  "voter-2",
	"voter3":  "voter-3",
	"voter-1": "voter-1",
	"voter-2": "voter-2",
	"voter-3": "voter-3",
}

func normalizeVoterLabel(label string) string {
	if canonical, ok := voterAliases[label]; ok {
		return canonical
	}
	return label
}
