// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

// Package cli implements the omt command-line interface: the cobra command
// tree and the OAuth2 flows each command drives. It lives outside package
// main so the whole CLI can be exercised in-process by tests, and so the
// docs generator (tools/gendocs) can walk the command tree without running
// it.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/schretzi/oauthmailtoken/internal/config"
)

// appName is the directory name looked up under the XDG config directories
// to find config.yaml, and the name the tool is invoked as.
const appName = "omt"

// httpTimeout bounds every token/device-code endpoint request.
const httpTimeout = 30 * time.Second

// Storage backends understood by loadTokenWithDefaultsNotice.
const (
	storageKeyring       = "keyring"
	keyringBackendSystem = "system"
)

// Process exit codes, following the Unix convention: 0 on success, 1 for a
// runtime failure, 2 for a usage error.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

// Errors reported for a config file that is missing something every command
// needs. They are sentinels so callers (and tests) can match on them with
// errors.Is rather than on their message text.
var (
	errNoGlobalSection   = errors.New("global section does not exist in config")
	errNoAccountsSection = errors.New("accounts section does not exist in config")
	errUnknownAccount    = errors.New("account does not exist in configfile")
)

// app carries what every command implementation needs beyond its own flags:
// where to write, where to read an interactive answer from, and the global
// flags shared by the whole tree.
//
// out and err are deliberately separate. out carries the command's actual
// result - the access token, or a report table - and nothing else, because
// `omt <account>` is used directly as mutt's imap_pass_cmd and inside
// `$(omt token <account>)`; anything extra on stdout is sent to the mail
// server as part of the bearer token. Every notice, prompt, warning and
// progress message goes to err instead.
type app struct {
	out io.Writer
	err io.Writer
	in  io.Reader

	verbose bool
	debug   bool
}

// infof writes an informational/progress message to the diagnostic stream.
func (a *app) infof(format string, v ...any) {
	fmt.Fprintf(a.err, format, v...)
}

// infoln is infof for a message that needs no formatting.
func (a *app) infoln(v ...any) {
	fmt.Fprintln(a.err, v...)
}

// outf writes to the result stream. Use it only for output that *is* the
// command's answer.
func (a *app) outf(format string, v ...any) {
	fmt.Fprintf(a.out, format, v...)
}

// outln is outf for a message that needs no formatting.
func (a *app) outln(v ...any) {
	fmt.Fprintln(a.out, v...)
}

// usageError marks an error as a misuse of the CLI - a bad flag, a wrong
// number of arguments - so Main can exit 2 and print the offending
// command's usage, instead of exiting 1 like a runtime failure.
type usageError struct {
	cmd *cobra.Command
	err error
}

func (e *usageError) Error() string { return e.err.Error() }
func (e *usageError) Unwrap() error { return e.err }

// usageArgs wraps a cobra positional-argument validator so the errors it
// produces are classified as usage errors.
func usageArgs(v cobra.PositionalArgs) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if err := v(cmd, args); err != nil {
			return &usageError{cmd: cmd, err: err}
		}
		return nil
	}
}

// Main runs the CLI with argv (typically os.Args[1:]) and returns the
// process exit code. It is the only entry point package main needs.
func Main(argv []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := Execute(ctx, argv, os.Stdout, os.Stderr, os.Stdin)
	if err == nil {
		return exitOK
	}

	var usageErr *usageError
	if errors.As(err, &usageErr) {
		fmt.Fprintln(os.Stderr, "error:", err)
		fmt.Fprint(os.Stderr, usageErr.cmd.UsageString())
		return exitUsage
	}

	fmt.Fprintln(os.Stderr, err)
	return exitFailure
}

// Execute builds a fresh command tree, points it at the given streams, and
// runs it. Tests call this directly with buffers so they exercise the real
// parsing and dispatch rather than a stand-in.
func Execute(ctx context.Context, argv []string, out, errOut io.Writer, in io.Reader) error {
	cmd := newRootCmd(&app{out: out, err: errOut, in: in})
	cmd.SetArgs(argv)
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetIn(in)
	return cmd.ExecuteContext(ctx)
}

// Root returns a fresh command tree wired to the process streams. It exists
// for tools/gendocs, which needs the tree in order to render it, without
// running anything.
func Root() *cobra.Command {
	return newRootCmd(&app{out: os.Stdout, err: os.Stderr, in: os.Stdin})
}

// newRootCmd assembles the whole command tree. It returns a new tree on
// every call: cobra accumulates flag state on a command, so sharing one
// instance across runs (or tests) leaks values between them.
func newRootCmd(a *app) *cobra.Command {
	var (
		authorizeFlag bool
		authflow      string
		testFlag      bool
	)

	cmd := &cobra.Command{
		Use:   appName + " [flags] <account>",
		Short: "Obtain and print a valid OAuth2 access token for a mail account",
		Long: `omt obtains and prints a valid OAuth2 access token for IMAP/POP/SMTP,
for use from mutt's imap_pass_cmd (or anything else that wants a bearer
token). State is kept in the OS keyring.

Run with just an account name to print a valid access token, transparently
authorizing (if no token exists yet) or refreshing (if the access token
expired) as needed. Only the token is written to stdout; every notice and
prompt goes to stderr, so the output is safe to use directly as a password
command.`,
		Example: `  # what mutt calls
  omt me@gmail.com

  # first-time interactive authorization
  omt authorize me@gmail.com

  # use the token from a script
  curl -H "Authorization: Bearer $(omt token me@gmail.com)" ...`,

		Args:              usageArgs(cobra.ExactArgs(1)),
		ValidArgsFunction: completeAccounts,

		// The caller (Main) decides how to render errors and which exit code
		// they map to, so cobra must not print them or dump usage itself.
		SilenceUsage:  true,
		SilenceErrors: true,

		RunE: func(cmd *cobra.Command, args []string) error {
			return runGet(cmd.Context(), a, args[0], authorizeFlag, authflow)
		},
	}

	cmd.PersistentFlags().BoolVarP(&a.verbose, "verbose", "v", false, "increase verbosity")
	cmd.PersistentFlags().BoolVarP(&a.debug, "debug", "d", false, "log raw HTTP responses from the OAuth2 endpoints")

	cmd.Flags().BoolVarP(&authorizeFlag, "authorize", "a", false, `re-run the interactive authorization flow (same as "omt authorize")`)
	cmd.Flags().StringVar(&authflow, "authflow", "", authflowFlagUsage)
	cmd.Flags().BoolVarP(&testFlag, "test", "t", false, "test IMAP/POP/SMTP endpoints (not yet implemented)")
	registerAuthflowCompletion(cmd)

	// Cobra prints its own errors for unknown/malformed flags; tag them so
	// they exit 2 rather than 1.
	cmd.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		return &usageError{cmd: c, err: err}
	})

	cmd.AddCommand(
		newAuthorizeCmd(a),
		newRefreshCmd(a),
		newListAccountsCmd(a),
		newStatusCmd(a),
		newTokenCmd(a),
		newDaemonCmd(a),
		newVersionCmd(a),
	)

	return cmd
}

// loadConfig locates and parses config.yaml, and verifies it declares the
// "accounts" section every command needs.
func loadConfig() (*config.Config, error) {
	cfgPath, err := config.LocateConfigFile(appName)
	if err != nil {
		return nil, fmt.Errorf("locating config: %w", err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}
	if cfg.Accounts == nil {
		return nil, errNoAccountsSection
	}
	return cfg, nil
}

// loadConfigWithProviders is loadConfig plus a check for the "global"
// section, which is where the provider definitions live - so it is what
// every command that actually talks to an OAuth2 endpoint should use.
func loadConfigWithProviders() (*config.Config, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	if cfg.Global == nil {
		return nil, errNoGlobalSection
	}
	return cfg, nil
}

// loadConfigAndAccount is loadConfigWithProviders plus a check that account
// is actually defined, returning that account's settings alongside the
// loaded config.
func loadConfigAndAccount(account string) (*config.Config, config.AccountConfig, error) {
	cfg, err := loadConfigWithProviders()
	if err != nil {
		return nil, config.AccountConfig{}, err
	}
	acc, ok := cfg.Accounts[account]
	if !ok {
		return nil, config.AccountConfig{}, errUnknownAccount
	}
	return cfg, acc, nil
}
