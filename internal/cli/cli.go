package cli

import (
	"fmt"
	"io"
)

const version = "librevote version 0.0.0-dev"

const usage = `LibreVote v1

Usage:
  librevote --help
  librevote help
  librevote version
  librevote <command> [arguments]

Commands:
  librevote init --db <path> --network <network_id>
  librevote trustee-election create --db <path> --id <id> --title <title> [--network <id>]
  librevote trustee nominate --db <path> --selection <id> --name <candidate_name> [--network <id>]
  librevote trustee vote --db <path> --selection <id> --voter <name> --candidates <name1,name2,name3> [--network <id>]
  librevote trustee result build --db <path> --selection <id> [--network <id>]
  librevote trustee consent --db <path> --name <name> --election <id> [--network <id>]
  librevote election create --db <path> --id <id> --title <title> --selection <id> [--options <opts>] [--network <id>]
  librevote tally-key contribute --db <path> --election <id> --name <name> [--network <id>]
  librevote tally-key build --db <path> --election <id> [--network <id>]
  librevote ballot cast --db <path> --election <id> --voter <label> --choice <option> [--network <id>]
  librevote tally build --db <path> --election <id> [--network <id>]
  librevote tally show --db <path> --election <id> [--network <id>]
  librevote node sync --db <path> --peer <url> [--scope <scope>] [--scope-id <id>] [--network <id>]
  librevote node serve --db <path> --listen <addr> [--network <id>]
  librevote node discover --db <path> [--bootstrap <multiaddrs>] [--listen <multiaddrs>] [--key <path>] [--network <id>] [--rendezvous <prefix>] [--mode <auto|server|client>] [--http-advertise <url>]
`

// Run executes the CLI surface for the MVP trustee-selection stage.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stdout, usage)
		return 0
	}

	switch args[0] {
	case "--help", "help":
		if len(args) != 1 {
			fmt.Fprintf(stderr, "error: %s accepts no arguments\n", args[0])
			return 2
		}
		fmt.Fprint(stdout, usage)
		return 0
	case "version":
		if len(args) != 1 {
			fmt.Fprint(stderr, "error: version accepts no arguments\n")
			return 2
		}
		fmt.Fprintln(stdout, version)
		return 0
	case "init":
		return cmdInit(args[1:], stdout, stderr)
	case "trustee-election":
		return cmdTrusteeElection(args[1:], stdout, stderr)
	case "trustee":
		return cmdTrustee(args[1:], stdout, stderr)
	case "election":
		return cmdElection(args[1:], stdout, stderr)
	case "tally-key":
		return cmdTallyKey(args[1:], stdout, stderr)
	case "ballot":
		return cmdBallot(args[1:], stdout, stderr)
	case "tally":
		return cmdTally(args[1:], stdout, stderr)
	case "node":
		return cmdNode(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "error: unknown command %q\n", args[0])
		return 2
	}
}
