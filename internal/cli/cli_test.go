package cli

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"librevote/internal/app"
	"librevote/internal/transport"
)

func TestRunNoArgsShowsHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(nil, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() exit code = %d; want 0", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q; want empty", stderr.String())
	}
	assertUsage(t, stdout.String())
}

func TestRunHelp(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "flag", args: []string{"--help"}},
		{name: "command", args: []string{"help"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := Run(tt.args, &stdout, &stderr)

			if code != 0 {
				t.Fatalf("Run() exit code = %d; want 0", code)
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q; want empty", stderr.String())
			}
			assertUsage(t, stdout.String())
		})
	}
}

func TestRunHelpExtraArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "flag", args: []string{"--help", "extra"}, want: "error: --help accepts no arguments\n"},
		{name: "command", args: []string{"help", "extra"}, want: "error: help accepts no arguments\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := Run(tt.args, &stdout, &stderr)

			if code != 2 {
				t.Fatalf("Run() exit code = %d; want 2", code)
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q; want empty", stdout.String())
			}
			if got := stderr.String(); got != tt.want {
				t.Fatalf("stderr = %q; want %q", got, tt.want)
			}
		})
	}
}

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run([]string{"version"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() exit code = %d; want 0", code)
	}
	if got, want := stdout.String(), "librevote version 0.0.0-dev\n"; got != want {
		t.Fatalf("stdout = %q; want %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q; want empty", stderr.String())
	}
}

func TestRunVersionExtraArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run([]string{"version", "extra"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("Run() exit code = %d; want 2", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q; want empty", stdout.String())
	}
	if got, want := stderr.String(), "error: version accepts no arguments\n"; got != want {
		t.Fatalf("stderr = %q; want %q", got, want)
	}
}

func TestRunUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run([]string{"unknown"}, &stdout, &stderr)

	if code == 0 {
		t.Fatal("Run() exit code = 0; want non-zero")
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q; want empty", stdout.String())
	}
	if got, want := stderr.String(), "error: unknown command \"unknown\"\n"; got != want {
		t.Fatalf("stderr = %q; want %q", got, want)
	}
}

func assertUsage(t *testing.T, out string) {
	t.Helper()

	for _, want := range []string{
		"Usage:",
		"librevote trustee-election create",
		"librevote trustee nominate",
		"librevote trustee result build",
		"librevote node sync",
		"librevote node serve",
		"librevote node discover",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q in:\n%s", want, out)
		}
	}
}

func TestInitMissingFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "no flags", args: []string{"init"}, want: "error: --db and --network are required\n"},
		{name: "only db", args: []string{"init", "--db", "/tmp"}, want: "error: --db and --network are required\n"},
		{name: "only network", args: []string{"init", "--network", "testnet"}, want: "error: --db and --network are required\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(tt.args, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("Run() exit code = %d; want 2", code)
			}
			if got := stderr.String(); got != tt.want {
				t.Fatalf("stderr = %q; want %q", got, tt.want)
			}
		})
	}
}

func TestInitValid(t *testing.T) {
	dataDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := Run([]string{"init", "--db", dataDir, "--network", "testnet"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run() exit code = %d; want 0, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "initialized database at "+dataDir) {
		t.Fatalf("stdout = %q; want init message", stdout.String())
	}
	if _, err := os.Stat(dataDir); err != nil {
		t.Fatalf("data dir not found: %v", err)
	}
}

func TestTrusteeElectionNoSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"trustee-election"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("Run() exit code = %d; want 2", code)
	}
	if got, want := stderr.String(), "error: trustee-election requires a subcommand: create\n"; got != want {
		t.Fatalf("stderr = %q; want %q", got, want)
	}
}

func TestTrusteeElectionUnknownSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"trustee-election", "unknown"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("Run() exit code = %d; want 2", code)
	}
	if got, want := stderr.String(), "error: unknown trustee-election subcommand \"unknown\"\n"; got != want {
		t.Fatalf("stderr = %q; want %q", got, want)
	}
}

func TestTrusteeElectionCreateMissingFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "no flags", args: []string{"trustee-election", "create"}, want: "error: --db, --id, and --title are required\n"},
		{name: "only db and id", args: []string{"trustee-election", "create", "--db", "/tmp", "--id", "ts-1"}, want: "error: --db, --id, and --title are required\n"},
		{name: "missing title only", args: []string{"trustee-election", "create", "--db", "/tmp", "--id", "ts-1", "--network", "testnet"}, want: "error: --db, --id, and --title are required\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(tt.args, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("Run() exit code = %d; want 2", code)
			}
			if got := stderr.String(); got != tt.want {
				t.Fatalf("stderr = %q; want %q", got, tt.want)
			}
		})
	}
}

func TestTrusteeNoSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"trustee"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("Run() exit code = %d; want 2", code)
	}
	if !strings.Contains(stderr.String(), "trustee requires a subcommand") {
		t.Fatalf("stderr = %q; want subcommand error", stderr.String())
	}
}

func TestTrusteeUnknownSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"trustee", "unknown"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("Run() exit code = %d; want 2", code)
	}
	if got, want := stderr.String(), "error: unknown trustee subcommand \"unknown\"\n"; got != want {
		t.Fatalf("stderr = %q; want %q", got, want)
	}
}

func TestTrusteeNominateMissingFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"trustee", "nominate"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("Run() exit code = %d; want 2", code)
	}
	if got, want := stderr.String(), "error: --db, --selection, and --name are required\n"; got != want {
		t.Fatalf("stderr = %q; want %q", got, want)
	}
}

func TestTrusteeVoteMissingFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"trustee", "vote"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("Run() exit code = %d; want 2", code)
	}
	if got, want := stderr.String(), "error: --db, --selection, --voter, and --candidates are required\n"; got != want {
		t.Fatalf("stderr = %q; want %q", got, want)
	}
}

func TestTrusteeResultNoSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"trustee", "result"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("Run() exit code = %d; want 2", code)
	}
	if got, want := stderr.String(), "error: trustee result requires a subcommand: build\n"; got != want {
		t.Fatalf("stderr = %q; want %q", got, want)
	}
}

func TestTrusteeResultBuildMissingFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"trustee", "result", "build"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("Run() exit code = %d; want 2", code)
	}
	if got, want := stderr.String(), "error: --db and --selection are required\n"; got != want {
		t.Fatalf("stderr = %q; want %q", got, want)
	}
}

func TestEndToEndTrusteeSelectionFlow(t *testing.T) {
	dataDir := t.TempDir()
	run := func(args []string) (string, string, int) {
		var stdout, stderr bytes.Buffer
		code := Run(args, &stdout, &stderr)
		return stdout.String(), stderr.String(), code
	}

	stdout, stderr, code := run([]string{"init", "--db", dataDir, "--network", "testnet"})
	if code != 0 {
		t.Fatalf("init failed: %s", stderr)
	}
	if !strings.Contains(stdout, "initialized database at") {
		t.Fatalf("unexpected init output: %s", stdout)
	}

	stdout, stderr, code = run([]string{"trustee-election", "create", "--db", dataDir, "--id", "ts-1", "--network", "testnet", "--title", "Test Election"})
	if code != 0 {
		t.Fatalf("trustee-election create failed: %s", stderr)
	}
	if !strings.Contains(stdout, "status: valid") {
		t.Fatalf("election not valid: %s", stdout)
	}
	t.Logf("election: %s", strings.TrimSpace(stdout))

	for _, name := range []string{"alice", "bob", "carol"} {
		stdout, stderr, code = run([]string{"trustee", "nominate", "--db", dataDir, "--selection", "ts-1", "--name", name, "--network", "testnet"})
		if code != 0 {
			t.Fatalf("nominate %s failed: %s", name, stderr)
		}
		if !strings.Contains(stdout, "status: valid") {
			t.Fatalf("nomination %s not valid: %s", name, stdout)
		}
		t.Logf("nomination %s: %s", name, strings.TrimSpace(stdout))
	}

	stdout, stderr, code = run([]string{"trustee", "vote", "--db", dataDir, "--selection", "ts-1", "--voter", "voter-1", "--candidates", "alice,bob", "--network", "testnet"})
	if code != 0 {
		t.Fatalf("vote failed: %s", stderr)
	}
	if !strings.Contains(stdout, "status: valid_for_tally") {
		t.Fatalf("vote not valid_for_tally: %s", stdout)
	}
	t.Logf("vote: %s", strings.TrimSpace(stdout))

	stdout, stderr, code = run([]string{"trustee", "result", "build", "--db", dataDir, "--selection", "ts-1", "--network", "testnet"})
	if code != 0 {
		t.Fatalf("result build failed: %s", stderr)
	}
	if !strings.Contains(stdout, "status: valid") {
		t.Fatalf("result not valid: %s", stdout)
	}
	t.Logf("result: %s", strings.TrimSpace(stdout))
}

func TestEndToEndActivationFlow(t *testing.T) {
	dataDir := t.TempDir()
	run := func(args []string) (string, string, int) {
		var stdout, stderr bytes.Buffer
		code := Run(args, &stdout, &stderr)
		return stdout.String(), stderr.String(), code
	}

	stdout, stderr, code := run([]string{"init", "--db", dataDir, "--network", "testnet"})
	if code != 0 {
		t.Fatalf("init failed: %s", stderr)
	}

	stdout, stderr, code = run([]string{"trustee-election", "create", "--db", dataDir, "--id", "ts-1", "--network", "testnet", "--title", "Test Election"})
	if code != 0 {
		t.Fatalf("trustee-election create failed: %s", stderr)
	}

	for _, name := range []string{"alice", "bob", "carol"} {
		stdout, stderr, code = run([]string{"trustee", "nominate", "--db", dataDir, "--selection", "ts-1", "--name", name, "--network", "testnet"})
		if code != 0 {
			t.Fatalf("nominate %s failed: %s", name, stderr)
		}
	}

	stdout, stderr, code = run([]string{"trustee", "vote", "--db", dataDir, "--selection", "ts-1", "--voter", "voter-1", "--candidates", "alice,bob", "--network", "testnet"})
	if code != 0 {
		t.Fatalf("vote failed: %s", stderr)
	}

	stdout, stderr, code = run([]string{"trustee", "result", "build", "--db", dataDir, "--selection", "ts-1", "--network", "testnet"})
	if code != 0 {
		t.Fatalf("result build failed: %s", stderr)
	}

	stdout, stderr, code = run([]string{"election", "create", "--db", dataDir, "--id", "an-1", "--title", "Anonymous", "--selection", "ts-1", "--network", "testnet"})
	if code != 0 {
		t.Fatalf("election create failed: %s", stderr)
	}
	if !strings.Contains(stdout, "status: valid") {
		t.Fatalf("election not valid: %s", stdout)
	}
	t.Logf("election: %s", strings.TrimSpace(stdout))

	for _, name := range []string{"alice", "bob", "carol"} {
		stdout, stderr, code = run([]string{"trustee", "consent", "--db", dataDir, "--name", name, "--election", "an-1", "--network", "testnet"})
		if code != 0 {
			t.Fatalf("consent %s failed: %s", name, stderr)
		}
		if !strings.Contains(stdout, "status: valid") {
			t.Fatalf("consent %s not valid: %s", name, stdout)
		}
		t.Logf("consent %s: %s", name, strings.TrimSpace(stdout))
	}

	for _, name := range []string{"alice", "bob", "carol"} {
		stdout, stderr, code = run([]string{"tally-key", "contribute", "--db", dataDir, "--election", "an-1", "--name", name, "--network", "testnet"})
		if code != 0 {
			t.Fatalf("contribute %s failed: %s", name, stderr)
		}
		if !strings.Contains(stdout, "status: valid") {
			t.Fatalf("contribution %s not valid: %s", name, stdout)
		}
		t.Logf("contribution %s: %s", name, strings.TrimSpace(stdout))
	}

	stdout, stderr, code = run([]string{"tally-key", "build", "--db", dataDir, "--election", "an-1", "--network", "testnet"})
	if code != 0 {
		t.Fatalf("tally-key build failed: %s", stderr)
	}
	if !strings.Contains(stdout, "status: valid") {
		t.Fatalf("key set not valid: %s", stdout)
	}
	t.Logf("key set: %s", strings.TrimSpace(stdout))
}

func TestParseFlagsRejectsUnknownFlag(t *testing.T) {
	_, err := parseFlags([]string{"--unknown", "value"}, initKnownFlags)
	if err == nil {
		t.Fatal("parseFlags accepted unknown flag")
	}
	if !strings.Contains(err.Error(), "unknown flag --unknown") {
		t.Fatalf("error = %q; want unknown flag", err)
	}
}

func TestParseFlagsRejectsPositionalArg(t *testing.T) {
	_, err := parseFlags([]string{"positional"}, initKnownFlags)
	if err == nil {
		t.Fatal("parseFlags accepted positional argument")
	}
	if !strings.Contains(err.Error(), "unexpected positional argument") {
		t.Fatalf("error = %q; want positional", err)
	}
}

func TestParseFlagsRejectsBareFlag(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "at end", args: []string{"--db"}},
		{name: "before next flag", args: []string{"--db", "--network", "net"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseFlags(tt.args, initKnownFlags)
			if err == nil {
				t.Fatal("parseFlags accepted bare flag")
			}
			if !strings.Contains(err.Error(), "requires a value") {
				t.Fatalf("error = %q; want requires value", err)
			}
		})
	}
}

func TestParseFlagsEmptyFlagName(t *testing.T) {
	_, err := parseFlags([]string{"--"}, initKnownFlags)
	if err == nil {
		t.Fatal("parseFlags accepted empty flag")
	}
	if !strings.Contains(err.Error(), "empty flag name") {
		t.Fatalf("error = %q; want empty flag name", err)
	}
}

func TestCliRejectsUnknownFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"trustee-election", "create", "--db", "/tmp", "--id", "ts-1", "--unknown", "x"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("Run() exit code = %d; want 2", code)
	}
	if !strings.Contains(stderr.String(), "unknown flag") {
		t.Fatalf("stderr = %q; want unknown flag", stderr.String())
	}
}

func TestCliRejectsPositional(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"trustee", "nominate", "--db", "/tmp", "--selection", "ts-1", "--name", "alice", "extra"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("Run() exit code = %d; want 2", code)
	}
	if !strings.Contains(stderr.String(), "unexpected positional argument") {
		t.Fatalf("stderr = %q; want positional", stderr.String())
	}
}

func TestCliRejectsBareFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"trustee-election", "create", "--db", "/tmp", "--id", "ts-1", "--network"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("Run() exit code = %d; want 2", code)
	}
	if !strings.Contains(stderr.String(), "requires a value") {
		t.Fatalf("stderr = %q; want requires value", stderr.String())
	}
}

func TestNetworkAutoDetectFromDB(t *testing.T) {
	dataDir := t.TempDir()
	run := func(args []string) (string, string, int) {
		var stdout, stderr bytes.Buffer
		code := Run(args, &stdout, &stderr)
		return stdout.String(), stderr.String(), code
	}

	stdout, stderr, code := run([]string{"init", "--db", dataDir, "--network", "testnet"})
	if code != 0 {
		t.Fatalf("init failed: %s", stderr)
	}
	_ = stdout

	stdout, stderr, code = run([]string{"trustee-election", "create", "--db", dataDir, "--id", "ts-1", "--title", "Test Election"})
	if code != 0 {
		t.Fatalf("trustee-election create without --network failed: %s", stderr)
	}
	if !strings.Contains(stdout, "status: valid") {
		t.Fatalf("election not valid: %s", stdout)
	}
	if !strings.Contains(stdout, "allowed voter labels: voter-1, voter-2, voter-3") {
		t.Fatalf("missing allowed voter labels: %s", stdout)
	}

	stdout, stderr, code = run([]string{"trustee", "nominate", "--db", dataDir, "--selection", "ts-1", "--name", "alice"})
	if code != 0 {
		t.Fatalf("nominate without --network failed: %s", stderr)
	}
	if !strings.Contains(stdout, "status: valid") {
		t.Fatalf("nomination not valid: %s", stdout)
	}

	stdout, stderr, code = run([]string{"trustee", "vote", "--db", dataDir, "--selection", "ts-1", "--voter", "voter-1", "--candidates", "alice"})
	if code != 0 {
		t.Fatalf("vote without --network failed: %s", stderr)
	}
	if !strings.Contains(stdout, "status: valid_for_tally") {
		t.Fatalf("vote not valid_for_tally: %s", stdout)
	}

	stdout, stderr, code = run([]string{"trustee", "result", "build", "--db", dataDir, "--selection", "ts-1"})
	if code != 0 {
		t.Fatalf("result build without --network failed: %s", stderr)
	}
	if !strings.Contains(stdout, "status: valid") {
		t.Fatalf("result not valid: %s", stdout)
	}
}

func TestNetworkRequiredWhenDBMissing(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"trustee-election", "create", "--db", "/nonexistent/path", "--id", "ts-1", "--title", "Test"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("Run() exit code = %d; want 2", code)
	}
	if !strings.Contains(stderr.String(), "--network is required") {
		t.Fatalf("stderr = %q; want network required", stderr.String())
	}
}

func TestVoterAliasNormalization(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "voter1", want: "voter-1"},
		{input: "voter2", want: "voter-2"},
		{input: "voter3", want: "voter-3"},
		{input: "voter-1", want: "voter-1"},
		{input: "voter-2", want: "voter-2"},
		{input: "voter-3", want: "voter-3"},
		{input: "other", want: "other"},
		{input: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeVoterLabel(tt.input)
			if got != tt.want {
				t.Fatalf("normalizeVoterLabel(%q) = %q; want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNodeNoSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"node"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("Run() exit code = %d; want 2", code)
	}
	if !strings.Contains(stderr.String(), "node requires a subcommand") {
		t.Fatalf("stderr = %q; want subcommand error", stderr.String())
	}
	if !strings.Contains(stderr.String(), "discover") {
		t.Fatalf("stderr missing 'discover' in subcommand list: %q", stderr.String())
	}
}

func TestNodeUnknownSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"node", "unknown"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("Run() exit code = %d; want 2", code)
	}
	if got, want := stderr.String(), "error: unknown node subcommand \"unknown\"\n"; got != want {
		t.Fatalf("stderr = %q; want %q", got, want)
	}
}

func TestNodeSyncMissingFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"node", "sync"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("Run() exit code = %d; want 2", code)
	}
	if got, want := stderr.String(), "error: --db and --peer are required\n"; got != want {
		t.Fatalf("stderr = %q; want %q", got, want)
	}
}

func TestNodeServeMissingFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"node", "serve"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("Run() exit code = %d; want 2", code)
	}
	if got, want := stderr.String(), "error: --db is required\n"; got != want {
		t.Fatalf("stderr = %q; want %q", got, want)
	}
}

func TestNodeSyncNetworkAutoDetect(t *testing.T) {
	dataDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := Run([]string{"init", "--db", dataDir, "--network", "testnet"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("init failed: %s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"node", "sync", "--db", dataDir, "--peer", "http://localhost:1"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected non-zero exit connecting to invalid peer, got 0: stdout=%q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "sync error") && !strings.Contains(stderr.String(), "inventory") {
		t.Logf("stdout: %s", stdout.String())
		t.Logf("stderr: %s", stderr.String())
	}
}

func TestVoterAliasInVoteCommand(t *testing.T) {
	dataDir := t.TempDir()
	run := func(args []string) (string, string, int) {
		var stdout, stderr bytes.Buffer
		code := Run(args, &stdout, &stderr)
		return stdout.String(), stderr.String(), code
	}

	_, stderr, code := run([]string{"init", "--db", dataDir, "--network", "testnet"})
	if code != 0 {
		t.Fatalf("init failed: %s", stderr)
	}

	stdout, stderr, code := run([]string{"trustee-election", "create", "--db", dataDir, "--id", "ts-1", "--title", "Test Election"})
	if code != 0 {
		t.Fatalf("election create failed: %s", stderr)
	}
	_ = stdout

	_, stderr, code = run([]string{"trustee", "nominate", "--db", dataDir, "--selection", "ts-1", "--name", "alice"})
	if code != 0 {
		t.Fatalf("nominate failed: %s", stderr)
	}

	stdout, stderr, code = run([]string{"trustee", "vote", "--db", dataDir, "--selection", "ts-1", "--voter", "voter1", "--candidates", "alice"})
	if code != 0 {
		t.Fatalf("vote with alias voter1 failed: %s", stderr)
	}
	if !strings.Contains(stdout, "voter: voter-1") {
		t.Fatalf("stdout = %q; want voter-1", stdout)
	}
	if !strings.Contains(stdout, "status: valid_for_tally") {
		t.Fatalf("vote not valid_for_tally: %s", stdout)
	}

	stdout, stderr, code = run([]string{"trustee", "vote", "--db", dataDir, "--selection", "ts-1", "--voter", "voter2", "--candidates", "alice"})
	if code != 0 {
		t.Fatalf("vote with alias voter2 failed: %s", stderr)
	}
	if !strings.Contains(stdout, "voter: voter-2") {
		t.Fatalf("stdout = %q; want voter-2", stdout)
	}
}

func TestNodeSyncRequiresScopeIDForIDScopedScope(t *testing.T) {
	dataDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := Run([]string{"init", "--db", dataDir, "--network", "testnet"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("init failed: %s", stderr.String())
	}
	stdout.Reset()
	stderr.Reset()

	code = Run([]string{"node", "sync", "--db", dataDir, "--peer", "http://localhost:1", "--scope", "trustee_selection_id"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), `requires --scope-id`) {
		t.Fatalf("expected scope-id required error, got: %s", stderr.String())
	}
}

func TestNodeSyncRequiresEmptyScopeIDForNetworkScope(t *testing.T) {
	dataDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := Run([]string{"init", "--db", dataDir, "--network", "testnet"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("init failed: %s", stderr.String())
	}
	stdout.Reset()
	stderr.Reset()

	code = Run([]string{"node", "sync", "--db", dataDir, "--peer", "http://localhost:1", "--scope", "network", "--scope-id", "ts-1"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), `requires empty --scope-id`) {
		t.Fatalf("expected empty scope-id required error, got: %s", stderr.String())
	}
}

func TestNodeSyncSuccessWithHTTPServer(t *testing.T) {
	dataDirA := t.TempDir()
	dataDirB := t.TempDir()

	run := func(args []string) (string, string, int) {
		var stdout, stderr bytes.Buffer
		code := Run(args, &stdout, &stderr)
		return stdout.String(), stderr.String(), code
	}

	stdout, stderr, code := run([]string{"init", "--db", dataDirA, "--network", "testnet"})
	if code != 0 {
		t.Fatalf("init A failed: %s", stderr)
	}
	t.Logf("init A: %s", stdout)

	stdout, stderr, code = run([]string{"trustee-election", "create", "--db", dataDirA, "--id", "ts-1", "--network", "testnet", "--title", "Test Election"})
	if code != 0 {
		t.Fatalf("election create failed: %s", stderr)
	}
	if !strings.Contains(stdout, "status: valid") {
		t.Fatalf("election not valid: %s", stdout)
	}
	t.Logf("election: %s", strings.TrimSpace(stdout))

	for _, name := range []string{"alice", "bob", "carol"} {
		stdout, stderr, code = run([]string{"trustee", "nominate", "--db", dataDirA, "--selection", "ts-1", "--name", name, "--network", "testnet"})
		if code != 0 {
			t.Fatalf("nominate %s failed: %s", name, stderr)
		}
		if !strings.Contains(stdout, "status: valid") {
			t.Fatalf("nomination %s not valid: %s", name, stdout)
		}
	}

	stdout, stderr, code = run([]string{"trustee", "vote", "--db", dataDirA, "--selection", "ts-1", "--voter", "voter-1", "--candidates", "alice", "--network", "testnet"})
	if code != 0 {
		t.Fatalf("vote failed: %s", stderr)
	}
	if !strings.Contains(stdout, "status: valid_for_tally") {
		t.Fatalf("vote not valid_for_tally: %s", stdout)
	}

	stdout, stderr, code = run([]string{"trustee", "result", "build", "--db", dataDirA, "--selection", "ts-1", "--network", "testnet"})
	if code != 0 {
		t.Fatalf("result build failed: %s", stderr)
	}
	if !strings.Contains(stdout, "status: valid") {
		t.Fatalf("result not valid: %s", stdout)
	}

	svcA, err := app.Open(dataDirA, "testnet")
	if err != nil {
		t.Fatalf("open svcA: %v", err)
	}
	defer svcA.Close()

	server := transport.NewServer(svcA, "testnet")
	testServer := httptest.NewServer(server.Handler())
	defer testServer.Close()

	stdout, stderr, code = run([]string{"init", "--db", dataDirB, "--network", "testnet"})
	if code != 0 {
		t.Fatalf("init B failed: %s", stderr)
	}

	stdout, stderr, code = run([]string{"node", "sync", "--db", dataDirB, "--peer", testServer.URL, "--scope", "network"})
	if code != 0 {
		t.Fatalf("node sync network scope: code=%d stderr=%s stdout=%s", code, stderr, stdout)
	}
	if !strings.Contains(stdout, "sync complete") {
		t.Fatalf("sync output missing 'sync complete': %s", stdout)
	}
	if !strings.Contains(stdout, "fetched:") || !strings.Contains(stdout, "ingested:") {
		t.Fatalf("sync output missing counts: %s", stdout)
	}
	t.Logf("sync network scope: %s", strings.TrimSpace(stdout))

	stdout, stderr, code = run([]string{"node", "sync", "--db", dataDirB, "--peer", testServer.URL, "--scope", "trustee_selection_id", "--scope-id", "ts-1"})
	if code != 0 {
		t.Fatalf("node sync scoped: code=%d stderr=%s stdout=%s", code, stderr, stdout)
	}
	if !strings.Contains(stdout, "sync complete") {
		t.Fatalf("scoped sync output missing 'sync complete': %s", stdout)
	}
	t.Logf("sync scoped: %s", strings.TrimSpace(stdout))

	ctx := context.Background()
	svcB, err := app.Open(dataDirB, "testnet")
	if err != nil {
		t.Fatalf("open svcB: %v", err)
	}
	defer svcB.Close()

	refsNetwork, err := svcB.ListServableObjectRefs(ctx, "network", "", nil)
	if err != nil {
		t.Fatalf("list network refs on B: %v", err)
	}
	if len(refsNetwork) == 0 {
		t.Fatal("expected at least one object from network scope sync")
	}
	t.Logf("node B network scope objects: %d", len(refsNetwork))

	refsScoped, err := svcB.ListServableObjectRefs(ctx, "trustee_selection_id", "ts-1", nil)
	if err != nil {
		t.Fatalf("list scoped refs on B: %v", err)
	}
	if len(refsScoped) == 0 {
		t.Fatal("expected objects from trustee_selection_id scope sync")
	}
	t.Logf("node B scoped objects: %d", len(refsScoped))
}

func TestNodeDiscoverMissingDB(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"node", "discover"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("Run() exit code = %d; want 2", code)
	}
	if got, want := stderr.String(), "error: --db is required\n"; got != want {
		t.Fatalf("stderr = %q; want %q", got, want)
	}
}

func TestNodeDiscoverHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Run() exit code = %d; want 0", code)
	}
	if !strings.Contains(stdout.String(), "node discover") {
		t.Fatalf("help missing node discover: %s", stdout.String())
	}
}

func TestNodeDiscoverNetworkAutoDetect(t *testing.T) {
	dataDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	code := Run([]string{"init", "--db", dataDir, "--network", "testnet"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("init failed: %s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"node", "discover", "--db", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("node discover failed: code=%d stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "discovery on network testnet") {
		t.Fatalf("output missing network: %s", out)
	}
	if !strings.Contains(out, "local_peer_id:") {
		t.Fatalf("output missing local_peer_id: %s", out)
	}
	if !strings.Contains(out, "namespace: /librevote/testnet/v1") {
		t.Fatalf("output missing namespace: %s", out)
	}
	if !strings.Contains(out, "discovered_peers: 0") {
		t.Fatalf("output missing discovered_peers: %s", out)
	}
}

func TestNodeDiscoverWithBootstrapFlag(t *testing.T) {
	dataDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	code := Run([]string{"init", "--db", dataDir, "--network", "testnet"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("init failed: %s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{
		"node", "discover",
		"--db", dataDir,
		"--listen", "/ip4/127.0.0.1/tcp/0",
		"--bootstrap", "/ip4/127.0.0.1/tcp/1/p2p/12D3KooWBadPeerId",
		"--key", dataDir + "/key",
		"--rendezvous", "/custom",
		"--mode", "client",
	}, &stdout, &stderr)
	if code != 6 {
		t.Fatalf("expected exit code 6 for unreachable bootstrap peer, got %d: stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stderr.String(), "bootstrap") {
		t.Fatalf("stderr missing bootstrap error: %s", stderr.String())
	}
}

func TestNodeDiscoverInvalidBootstrapMultiaddr(t *testing.T) {
	dataDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	code := Run([]string{"init", "--db", dataDir, "--network", "testnet"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("init failed: %s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{
		"node", "discover",
		"--db", dataDir,
		"--bootstrap", "garbage-not-a-multiaddr",
	}, &stdout, &stderr)
	if code != 6 {
		t.Fatalf("expected exit code 6 for invalid bootstrap multiaddr, got %d: stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "bootstrap") {
		t.Fatalf("stderr missing bootstrap error: %s", stderr.String())
	}
}

func TestNodeDiscoverNoBootstrapSelfInfo(t *testing.T) {
	dataDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	code := Run([]string{"init", "--db", dataDir, "--network", "testnet"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("init failed: %s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"node", "discover", "--db", dataDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("no-bootstrap discover should succeed: code=%d stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "discovery on network testnet") {
		t.Fatalf("output missing network: %s", out)
	}
	if !strings.Contains(out, "local_peer_id:") {
		t.Fatalf("output missing local_peer_id: %s", out)
	}
	if !strings.Contains(out, "discovered_peers: 0") {
		t.Fatalf("output missing discovered_peers: %s", out)
	}
	if !strings.Contains(out, "mode: auto") {
		t.Fatalf("output missing mode: %s", out)
	}
}

func TestNodeDiscoverUnknownFlags(t *testing.T) {
	dataDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	code := Run([]string{"init", "--db", dataDir, "--network", "testnet"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("init failed: %s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"node", "discover", "--db", dataDir, "--unknown-flag", "val"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit code 2 for unknown flag, got %d", code)
	}
	if !strings.Contains(stderr.String(), "unknown flag") {
		t.Fatalf("expected unknown flag error, got: %s", stderr.String())
	}
}

func TestNodeDiscoverValidatesModeFlag(t *testing.T) {
	dataDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	code := Run([]string{"init", "--db", dataDir, "--network", "testnet"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("init failed: %s", stderr.String())
	}

	for _, mode := range []string{"auto", "server", "client"} {
		t.Run(mode, func(t *testing.T) {
			stdout.Reset()
			stderr.Reset()
			code := Run([]string{
				"node", "discover",
				"--db", dataDir,
				"--mode", mode,
			}, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("mode=%q failed: code=%d stderr=%s", mode, code, stderr.String())
			}
			if !strings.Contains(stdout.String(), "mode: "+mode) {
				t.Fatalf("output missing effective mode %q: %s", mode, stdout.String())
			}
		})
	}
}

func TestNodeDiscoverRejectsInvalidMode(t *testing.T) {
	dataDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	code := Run([]string{"init", "--db", dataDir, "--network", "testnet"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("init failed: %s", stderr.String())
	}

	for _, mode := range []string{"invalid", "automatic", "peer", ""} {
		t.Run("mode="+mode, func(t *testing.T) {
			args := []string{"node", "discover", "--db", dataDir}
			if mode != "" {
				args = append(args, "--mode", mode)
			}
			stdout.Reset()
			stderr.Reset()
			code := Run(args, &stdout, &stderr)
			if mode == "" {
				// Empty mode defaults to "auto" which is valid
				if code != 0 {
					t.Fatalf("empty mode (defaults to auto) should succeed: code=%d stderr=%s", code, stderr.String())
				}
				if !strings.Contains(stdout.String(), "mode: auto") {
					t.Fatalf("output missing default mode auto: %s", stdout.String())
				}
			} else {
				if code != 2 {
					t.Fatalf("mode=%q should exit 2, got %d", mode, code)
				}
				if !strings.Contains(stderr.String(), "invalid --mode") {
					t.Fatalf("stderr missing invalid mode error for %q: %s", mode, stderr.String())
				}
			}
		})
	}
}

func TestNodeDiscoverHTTPAdvertiseFlag(t *testing.T) {
	dataDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	code := Run([]string{"init", "--db", dataDir, "--network", "testnet"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("init failed: %s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{
		"node", "discover",
		"--db", dataDir,
		"--http-advertise", "http://myhost:9090",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("discover with http-advertise failed: code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "discovery on network testnet") {
		t.Fatalf("output missing discovery: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "local_peer_id:") {
		t.Fatalf("output missing local_peer_id: %s", stdout.String())
	}
}

func TestNodeDiscoverNetworkRequiredNoDB(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"node", "discover", "--db", "/nonexistent/path"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "--network is required") {
		t.Fatalf("expected network required, got: %s", stderr.String())
	}
}
