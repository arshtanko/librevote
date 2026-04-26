package cli

import (
	"bytes"
	"strings"
	"testing"
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
		"librevote node ...",
		"librevote trustee-selection ...",
		"librevote object ...",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q in:\n%s", want, out)
		}
	}
}
