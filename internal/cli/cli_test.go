// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

package cli

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"

	"github.com/schretzi/oauthmailtoken/internal/token"
)

func TestRootPrintsValidStoredAccessToken(t *testing.T) {
	withXDGConfig(t, testConfigYAML)
	keyring.MockInit()

	want := &token.Token{
		AccessToken:           "already-valid-access-token",
		AccessTokenExpiration: time.Now().Add(time.Hour).Format(time.RFC3339),
		RefreshToken:          "refresh-abc",
	}
	if err := token.Store("me@gmail.com", want); err != nil {
		t.Fatal(err)
	}

	stdout, _, err := execute(t, "me@gmail.com")
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}
	if got := trimTrailingNewline(stdout); got != want.AccessToken {
		t.Errorf("stdout = %q, want exactly %q", stdout, want.AccessToken)
	}
}

func TestRootUnknownAccount(t *testing.T) {
	withXDGConfig(t, testConfigYAML)
	keyring.MockInit()

	if _, _, err := execute(t, "nobody@gmail.com"); !errors.Is(err, errUnknownAccount) {
		t.Fatalf("err = %v, want errUnknownAccount", err)
	}
}

// The whole point of the stdout/stderr split: a config without an explicit
// keyring-backend prints a notice, and that notice must not land in the
// output mutt uses as the bearer token.
func TestNoticesGoToStderrNotStdout(t *testing.T) {
	withXDGConfig(t, `
global:
  storage: keyring
  google:
    token_endpoint: https://example.invalid/token
    client_id: cid
accounts:
  me@gmail.com:
    provider: google
`)
	keyring.MockInit()

	if err := token.Store("me@gmail.com", &token.Token{
		AccessToken:           "the-token",
		AccessTokenExpiration: time.Now().Add(time.Hour).Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := execute(t, "me@gmail.com")
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}
	if got := trimTrailingNewline(stdout); got != "the-token" {
		t.Errorf("stdout = %q, want exactly the token", stdout)
	}
	if !strings.Contains(stderr, "Keyring Backend not set") {
		t.Errorf("expected the backend notice on stderr, got: %q", stderr)
	}
}

func TestListAccountsCommand(t *testing.T) {
	withXDGConfig(t, `
accounts:
  b@gmail.com:
    provider: google
  a@gmail.com:
    provider: google
`)
	keyring.MockInit()

	stdout, _, err := execute(t, "list-accounts")
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}
	want := []string{"a@gmail.com", "b@gmail.com"} // sorted
	got := lines(stdout)
	if len(got) != len(want) {
		t.Fatalf("got %d lines %v, want %v", len(got), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestListAccountsCommandNoAccountsSection(t *testing.T) {
	withXDGConfig(t, "global:\n  storage: keyring\n")
	keyring.MockInit()

	if _, _, err := execute(t, "list-accounts"); !errors.Is(err, errNoAccountsSection) {
		t.Fatalf("err = %v, want errNoAccountsSection", err)
	}
}

func TestListAccountsCommandRejectsAnArgument(t *testing.T) {
	withXDGConfig(t, testConfigYAML)
	keyring.MockInit()

	_, _, err := execute(t, "list-accounts", "me@gmail.com")
	assertUsageError(t, err)
}

func TestTokenCommandPrintsOnlyTheStoredToken(t *testing.T) {
	withXDGConfig(t, testConfigYAML)
	keyring.MockInit()

	stored := &token.Token{
		AccessToken:           "stored-access-token",
		AccessTokenExpiration: time.Now().Add(time.Hour).Format(time.RFC3339),
		RefreshToken:          "refresh-abc",
	}
	if err := token.Store("me@gmail.com", stored); err != nil {
		t.Fatal(err)
	}

	stdout, _, err := execute(t, "token", "me@gmail.com")
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}
	if got := trimTrailingNewline(stdout); got != stored.AccessToken {
		t.Errorf("stdout = %q, want exactly %q", stdout, stored.AccessToken)
	}
}

func TestTokenCommandNoStoredToken(t *testing.T) {
	withXDGConfig(t, testConfigYAML)
	keyring.MockInit()

	if _, _, err := execute(t, "token", "me@gmail.com"); err == nil {
		t.Fatal("expected an error when no token is stored yet")
	}
}

func TestTokenCommandUnknownAccount(t *testing.T) {
	withXDGConfig(t, testConfigYAML)
	keyring.MockInit()

	if _, _, err := execute(t, "token", "nobody@gmail.com"); !errors.Is(err, errUnknownAccount) {
		t.Fatalf("err = %v, want errUnknownAccount", err)
	}
}

func TestTokenCommandExpiredTokenStillPrintedWithWarning(t *testing.T) {
	withXDGConfig(t, testConfigYAML)
	keyring.MockInit()

	expired := &token.Token{
		AccessToken:           "expired-but-still-stored",
		AccessTokenExpiration: time.Now().Add(-time.Hour).Format(time.RFC3339),
		RefreshToken:          "refresh-abc",
	}
	if err := token.Store("me@gmail.com", expired); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := execute(t, "token", "me@gmail.com")
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}
	// The expiry warning must go to stderr: stdout stays exactly the token
	// so it is safe to embed in a command substitution.
	if got := trimTrailingNewline(stdout); got != expired.AccessToken {
		t.Errorf("stdout = %q, want exactly %q", stdout, expired.AccessToken)
	}
	if !strings.Contains(stderr, "expired") {
		t.Errorf("expected an expiry warning on stderr, got: %q", stderr)
	}
}

func TestTokenCommandRequiresAnAccount(t *testing.T) {
	withXDGConfig(t, testConfigYAML)
	keyring.MockInit()

	_, _, err := execute(t, "token")
	assertUsageError(t, err)
}

func TestVersionCommand(t *testing.T) {
	stdout, _, err := execute(t, "version")
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}
	if !strings.HasPrefix(stdout, "omt ") {
		t.Errorf("stdout = %q, want it to start with %q", stdout, "omt ")
	}
	if !strings.Contains(stdout, "go:") {
		t.Errorf("expected the Go version line, got: %q", stdout)
	}
	// The GPL's "Appropriate Legal Notices": copyright, no-warranty,
	// redistributable under the GPL, and where to read it.
	for _, want := range []string{"Copyright (C)", "GPLv3+", "NO WARRANTY", "gnu.org/licenses"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("version output missing licence notice %q, got:\n%s", want, stdout)
		}
	}
}

// --- flag / argument parsing ------------------------------------------------

func TestUnknownFlagIsAUsageError(t *testing.T) {
	withXDGConfig(t, testConfigYAML)
	keyring.MockInit()

	_, _, err := execute(t, "--nope", "me@gmail.com")
	assertUsageError(t, err)
}

func TestRootRejectsExtraArguments(t *testing.T) {
	withXDGConfig(t, testConfigYAML)
	keyring.MockInit()

	_, _, err := execute(t, "me@gmail.com", "extra@gmail.com")
	assertUsageError(t, err)
}

func TestRootRequiresAnAccount(t *testing.T) {
	withXDGConfig(t, testConfigYAML)
	keyring.MockInit()

	_, _, err := execute(t)
	assertUsageError(t, err)
}

// Flags may appear before or after the positional argument, which is how the
// original Python CLI behaved and what existing .muttrc lines rely on.
func TestFlagsMayFollowThePositionalArgument(t *testing.T) {
	withXDGConfig(t, testConfigYAML)
	keyring.MockInit()

	if err := token.Store("me@gmail.com", &token.Token{
		AccessToken:           "tok",
		AccessTokenExpiration: time.Now().Add(time.Hour).Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}

	for _, argv := range [][]string{
		{"-v", "me@gmail.com"},
		{"me@gmail.com", "-v"},
		{"--verbose", "me@gmail.com"},
	} {
		stdout, stderr, err := execute(t, argv...)
		if err != nil {
			t.Fatalf("execute(%v) returned error: %v", argv, err)
		}
		if got := trimTrailingNewline(stdout); got != "tok" {
			t.Errorf("execute(%v) stdout = %q, want %q", argv, stdout, "tok")
		}
		// -v adds the "Access Token: " label, on stderr.
		if !strings.Contains(stderr, "Access Token:") {
			t.Errorf("execute(%v) stderr = %q, want the verbose label", argv, stderr)
		}
	}
}

func TestHelpExitsCleanly(t *testing.T) {
	stdout, _, err := execute(t, "--help")
	if err != nil {
		t.Fatalf("--help returned error: %v", err)
	}
	for _, want := range []string{"authorize", "refresh", "list-accounts", "status", "token", "daemon"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("help output does not mention %q:\n%s", want, stdout)
		}
	}
}

// --- shell completion -------------------------------------------------------

func TestCompleteAccountsOffersConfiguredNames(t *testing.T) {
	withXDGConfig(t, `
accounts:
  alice@gmail.com:
    provider: google
  bob@gmail.com:
    provider: google
`)

	got, directive := completeAccounts(nil, nil, "")
	want := []string{"alice@gmail.com", "bob@gmail.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("completions = %v, want %v", got, want)
	}
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Errorf("directive = %v, want NoFileComp", directive)
	}

	if got, _ := completeAccounts(nil, nil, "al"); strings.Join(got, ",") != "alice@gmail.com" {
		t.Errorf("prefix-filtered completions = %v, want [alice@gmail.com]", got)
	}
	if got, _ := completeAccounts(nil, []string{"alice@gmail.com"}, ""); got != nil {
		t.Errorf("expected no completions once the account is given, got %v", got)
	}
}

// Completion must stay silent when there is no usable config, rather than
// spraying an error into the user's prompt.
func TestCompleteAccountsIsSilentWithoutConfig(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_DIRS", t.TempDir())

	if got, _ := completeAccounts(nil, nil, ""); got != nil {
		t.Errorf("expected no completions without a config, got %v", got)
	}
}

func TestCompletionScriptsAreGenerated(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		stdout, _, err := execute(t, "completion", shell)
		if err != nil {
			t.Fatalf("completion %s returned error: %v", shell, err)
		}
		if !strings.Contains(stdout, appName) {
			t.Errorf("completion %s script does not mention %q", shell, appName)
		}
	}
}

// --- helpers ----------------------------------------------------------------

func assertUsageError(t *testing.T, err error) {
	t.Helper()

	if err == nil {
		t.Fatal("expected an error")
	}
	var usageErr *usageError
	if !errors.As(err, &usageErr) {
		t.Fatalf("err = %v (%T), want a *usageError so the process exits %d", err, err, exitUsage)
	}
	if usageErr.cmd == nil {
		t.Error("usageError carries no command, so Main cannot print its usage")
	}
}

func TestLoadConfigRequiresGlobalSectionForProviderCommands(t *testing.T) {
	withXDGConfig(t, `
accounts:
  me@gmail.com:
    provider: google
`)
	if _, err := loadConfigWithProviders(); !errors.Is(err, errNoGlobalSection) {
		t.Fatalf("err = %v, want errNoGlobalSection", err)
	}
	if _, err := loadConfig(); err != nil {
		t.Errorf("loadConfig should not require the global section: %v", err)
	}
}
