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

Command groups:
  librevote init
  librevote node ...
  librevote key ...
  librevote peer ...
  librevote sync ...
  librevote trustee-selection ...
  librevote trustee ...
  librevote election ...
  librevote token ...
  librevote vote ...
  librevote tally ...
  librevote result ...
  librevote object ...
`

// Run executes the minimal CLI surface for the repository foundation stage.
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
	default:
		fmt.Fprintf(stderr, "error: unknown command %q\n", args[0])
		return 2
	}
}
