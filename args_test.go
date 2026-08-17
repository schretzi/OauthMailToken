package main

import (
	"errors"
	"testing"
)

func TestParseArgsAccountOnly(t *testing.T) {
	a, err := parseArgs([]string{"me@example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.Account != "me@example.com" {
		t.Errorf("Account = %q", a.Account)
	}
	if a.Command != CmdGet {
		t.Errorf("Command = %q, want %q", a.Command, CmdGet)
	}
	if a.Verbose || a.Debug || a.Authorize || a.Test || a.Authflow != "" {
		t.Errorf("unexpected non-default flags: %+v", a)
	}
}

func TestParseArgsFlagsBeforeAndAfterPositional(t *testing.T) {
	a, err := parseArgs([]string{"-v", "me@example.com", "--authorize", "--authflow", "devicecode"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.Account != "me@example.com" {
		t.Errorf("Account = %q", a.Account)
	}
	if !a.Verbose || !a.Authorize {
		t.Errorf("expected verbose+authorize to be set: %+v", a)
	}
	if a.Authflow != "devicecode" {
		t.Errorf("Authflow = %q", a.Authflow)
	}
}

func TestParseArgsAuthflowEqualsForm(t *testing.T) {
	a, err := parseArgs([]string{"--authflow=authcode", "me@example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.Authflow != "authcode" {
		t.Errorf("Authflow = %q", a.Authflow)
	}
}

func TestParseArgsLongAndShortFlags(t *testing.T) {
	a, err := parseArgs([]string{"--verbose", "--debug", "-t", "me@example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !a.Verbose || !a.Debug || !a.Test {
		t.Errorf("expected verbose+debug+test to be set: %+v", a)
	}
}

func TestParseArgsMissingAccount(t *testing.T) {
	if _, err := parseArgs([]string{"-v"}); err == nil {
		t.Fatal("expected error for missing account")
	}
}

func TestParseArgsTooManyPositional(t *testing.T) {
	if _, err := parseArgs([]string{"a@example.com", "b@example.com"}); err == nil {
		t.Fatal("expected error for extra positional argument")
	}
}

func TestParseArgsUnknownFlag(t *testing.T) {
	if _, err := parseArgs([]string{"--bogus", "a@example.com"}); err == nil {
		t.Fatal("expected error for unknown flag")
	}
}

func TestParseArgsHelp(t *testing.T) {
	_, err := parseArgs([]string{"--help"})
	if !errors.Is(err, ErrHelp) {
		t.Fatalf("expected ErrHelp, got %v", err)
	}

	_, err = parseArgs([]string{"-h"})
	if !errors.Is(err, ErrHelp) {
		t.Fatalf("expected ErrHelp, got %v", err)
	}
}

func TestParseArgsAuthflowMissingValue(t *testing.T) {
	if _, err := parseArgs([]string{"me@example.com", "--authflow"}); err == nil {
		t.Fatal("expected error for --authflow without a value")
	}
}

func TestParseArgsAuthorizeCommand(t *testing.T) {
	a, err := parseArgs([]string{"authorize", "-v", "me@example.com", "--authflow", "devicecode"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.Command != CmdAuthorize {
		t.Errorf("Command = %q, want %q", a.Command, CmdAuthorize)
	}
	if a.Account != "me@example.com" {
		t.Errorf("Account = %q", a.Account)
	}
	if !a.Verbose {
		t.Error("expected verbose to be set")
	}
	if a.Authflow != "devicecode" {
		t.Errorf("Authflow = %q", a.Authflow)
	}
}

func TestParseArgsRefreshCommand(t *testing.T) {
	a, err := parseArgs([]string{"refresh", "me@example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.Command != CmdRefresh {
		t.Errorf("Command = %q, want %q", a.Command, CmdRefresh)
	}
	if a.Account != "me@example.com" {
		t.Errorf("Account = %q", a.Account)
	}
}

func TestParseArgsRefreshCommandNoAccountMeansAll(t *testing.T) {
	a, err := parseArgs([]string{"refresh"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.Command != CmdRefresh {
		t.Errorf("Command = %q, want %q", a.Command, CmdRefresh)
	}
	if a.Account != "" {
		t.Errorf("Account = %q, want empty (all accounts)", a.Account)
	}
}

func TestParseArgsRefreshCommandTooManyArgs(t *testing.T) {
	if _, err := parseArgs([]string{"refresh", "a@example.com", "b@example.com"}); err == nil {
		t.Fatal("expected error for refresh with more than one account")
	}
}

func TestParseArgsListAccountsCommand(t *testing.T) {
	a, err := parseArgs([]string{"list-accounts"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.Command != CmdListAccounts {
		t.Errorf("Command = %q, want %q", a.Command, CmdListAccounts)
	}
	if a.Account != "" {
		t.Errorf("Account = %q, want empty", a.Account)
	}
}

func TestParseArgsListAccountsRejectsAccountArg(t *testing.T) {
	if _, err := parseArgs([]string{"list-accounts", "me@example.com"}); err == nil {
		t.Fatal("expected error: list-accounts does not take an account argument")
	}
}

func TestParseArgsStatusCommandNoAccount(t *testing.T) {
	a, err := parseArgs([]string{"status"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.Command != CmdStatus {
		t.Errorf("Command = %q, want %q", a.Command, CmdStatus)
	}
	if a.Account != "" {
		t.Errorf("Account = %q, want empty (all accounts)", a.Account)
	}
}

func TestParseArgsStatusCommandWithAccount(t *testing.T) {
	a, err := parseArgs([]string{"status", "me@example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.Command != CmdStatus {
		t.Errorf("Command = %q, want %q", a.Command, CmdStatus)
	}
	if a.Account != "me@example.com" {
		t.Errorf("Account = %q, want %q", a.Account, "me@example.com")
	}
}

func TestParseArgsStatusCommandTooManyArgs(t *testing.T) {
	if _, err := parseArgs([]string{"status", "a@example.com", "b@example.com"}); err == nil {
		t.Fatal("expected error for status with more than one account")
	}
}

func TestParseArgsTokenCommand(t *testing.T) {
	a, err := parseArgs([]string{"token", "me@example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.Command != CmdToken {
		t.Errorf("Command = %q, want %q", a.Command, CmdToken)
	}
	if a.Account != "me@example.com" {
		t.Errorf("Account = %q, want %q", a.Account, "me@example.com")
	}
}

func TestParseArgsTokenCommandRequiresAccount(t *testing.T) {
	if _, err := parseArgs([]string{"token"}); err == nil {
		t.Fatal("expected error: token requires an account argument")
	}
}

func TestParseArgsTokenCommandTooManyArgs(t *testing.T) {
	if _, err := parseArgs([]string{"token", "a@example.com", "b@example.com"}); err == nil {
		t.Fatal("expected error for token with more than one account")
	}
}

func TestParseArgsCompletionCommand(t *testing.T) {
	for _, shell := range []string{"bash", "zsh"} {
		a, err := parseArgs([]string{"completion", shell})
		if err != nil {
			t.Fatalf("unexpected error for shell %q: %v", shell, err)
		}
		if a.Command != CmdCompletion {
			t.Errorf("Command = %q, want %q", a.Command, CmdCompletion)
		}
		if a.Shell != shell {
			t.Errorf("Shell = %q, want %q", a.Shell, shell)
		}
	}
}

func TestParseArgsCompletionCommandRequiresShell(t *testing.T) {
	if _, err := parseArgs([]string{"completion"}); err == nil {
		t.Fatal("expected error: completion requires a shell argument")
	}
}

func TestParseArgsCompletionCommandRejectsUnknownShell(t *testing.T) {
	if _, err := parseArgs([]string{"completion", "fish"}); err == nil {
		t.Fatal("expected error for unsupported shell")
	}
}

func TestParseArgsDaemonCommand(t *testing.T) {
	a, err := parseArgs([]string{"daemon"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.Command != CmdDaemon {
		t.Errorf("Command = %q, want %q", a.Command, CmdDaemon)
	}
	if a.Account != "" {
		t.Errorf("Account = %q, want empty", a.Account)
	}
}

func TestParseArgsDaemonCommandRejectsAccountArg(t *testing.T) {
	if _, err := parseArgs([]string{"daemon", "me@example.com"}); err == nil {
		t.Fatal("expected error: daemon does not take an account argument")
	}
}

func TestParseArgsDaemonCommandAcceptsDebugFlag(t *testing.T) {
	a, err := parseArgs([]string{"daemon", "-d"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !a.Debug {
		t.Error("expected debug to be set")
	}
}

func TestParseArgsSubcommandMustBeFirst(t *testing.T) {
	// "authorize" appearing after the account is just a (second) positional
	// argument, not a subcommand - and thus a "too many arguments" error.
	if _, err := parseArgs([]string{"me@example.com", "authorize"}); err == nil {
		t.Fatal("expected error: authorize is only recognized as the first argument")
	}
}
