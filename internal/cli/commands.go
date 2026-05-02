package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"librevote/internal/app"
	"librevote/internal/domain"
	"librevote/internal/sync"
	"librevote/internal/transport"
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
		fmt.Fprintln(stderr, "error: trustee requires a subcommand: nominate, vote, result")
		return 2
	}
	switch args[0] {
	case "nominate":
		return cmdTrusteeNominate(args[1:], stdout, stderr)
	case "vote":
		return cmdTrusteeVote(args[1:], stdout, stderr)
	case "result":
		return cmdTrusteeResult(args[1:], stdout, stderr)
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

func cmdNode(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "error: node requires a subcommand: sync, serve")
		return 2
	}
	switch args[0] {
	case "sync":
		return cmdNodeSync(args[1:], stdout, stderr)
	case "serve":
		return cmdNodeServe(args[1:], stdout, stderr)
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

var initKnownFlags = flagSet("db", "network")

var trusteeElectionCreateKnownFlags = flagSet("db", "id", "network", "title")

var trusteeNominateKnownFlags = flagSet("db", "selection", "name", "network")

var trusteeVoteKnownFlags = flagSet("db", "selection", "voter", "candidates", "network")

var trusteeResultBuildKnownFlags = flagSet("db", "selection", "network")

var nodeSyncKnownFlags = flagSet("db", "peer", "scope", "scope-id", "network")

var nodeServeKnownFlags = flagSet("db", "listen", "network")

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
