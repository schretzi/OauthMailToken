package main

import (
	"errors"
	"fmt"
	"strings"
)

// ErrHelp is returned by parseArgs when -h/--help was requested.
var ErrHelp = errors.New("help requested")

// Command identifies which subcommand was invoked.
type Command string

const (
	// CmdGet is the default (no subcommand given): print a valid access
	// token, transparently authorizing/refreshing as needed. This is what
	// mutt (or any --pass_cmd style integration) calls.
	CmdGet Command = "get"
	// CmdAuthorize is a shorthand for `omt --authorize <account>`: always
	// runs the interactive authorization flow.
	CmdAuthorize Command = "authorize"
	// CmdRefresh forces a refresh-token exchange, regardless of whether the
	// current access token is still valid, for the given account, or for
	// every configured account that has a refresh token stored if none is
	// given.
	CmdRefresh Command = "refresh"
	// CmdListAccounts prints the account names configured in config.yaml,
	// one per line. It takes no account argument.
	CmdListAccounts Command = "list-accounts"
	// CmdStatus prints authorization status (authorized?, access token
	// valid?, expiration) for every configured account, or just the given
	// one if an account argument is provided.
	CmdStatus Command = "status"
	// CmdToken prints *only* the currently stored access token for the
	// given account, straight from the keyring - no authorizing, no
	// refreshing, no other output on stdout - so it can be embedded in a
	// command substitution and passed to another program.
	CmdToken Command = "token"
	// CmdCompletion prints a shell completion script (bash or zsh) to
	// stdout, for `source <(omt completion bash)` / `... zsh`.
	CmdCompletion Command = "completion"
	// CmdDaemon runs a long-lived process that periodically checks every
	// configured account's stored access token and refreshes it if it will
	// expire soon, so tokens stay fresh across sleep/wake cycles without
	// depending on an external timer (cron/launchd) firing promptly. It
	// takes no account argument.
	CmdDaemon Command = "daemon"
)

// Args holds the parsed command-line arguments.
type Args struct {
	Command   Command
	Account   string
	Verbose   bool
	Debug     bool
	Authorize bool
	Authflow  string
	Test      bool
	// Shell is the positional argument to the "completion" command
	// ("bash" or "zsh"); unused for every other command.
	Shell string
}

// parseArgs parses args (typically os.Args[1:]).
//
// If the first argument is a known subcommand ("authorize", "refresh",
// "list-accounts", "status", "token", "completion", or "daemon"), it must
// come first, before any flags; everything after it is parsed the same way
// as the default (no-subcommand) invocation. Unlike Go's flag package, flags
// may otherwise appear anywhere relative to the positional "account"
// argument, matching this program's original Python/argparse-based CLI.
func parseArgs(args []string) (*Args, error) {
	a := &Args{Command: CmdGet}

	rest := args
	if len(args) > 0 {
		switch args[0] {
		case string(CmdAuthorize):
			a.Command = CmdAuthorize
			rest = args[1:]
		case string(CmdRefresh):
			a.Command = CmdRefresh
			rest = args[1:]
		case string(CmdListAccounts):
			a.Command = CmdListAccounts
			rest = args[1:]
		case string(CmdStatus):
			a.Command = CmdStatus
			rest = args[1:]
		case string(CmdToken):
			a.Command = CmdToken
			rest = args[1:]
		case string(CmdCompletion):
			a.Command = CmdCompletion
			rest = args[1:]
		case string(CmdDaemon):
			a.Command = CmdDaemon
			rest = args[1:]
		}
	}

	boolFlags := map[string]*bool{
		"-v": &a.Verbose, "--verbose": &a.Verbose,
		"-d": &a.Debug, "--debug": &a.Debug,
		"-a": &a.Authorize, "--authorize": &a.Authorize,
		"-t": &a.Test, "--test": &a.Test,
	}

	var positional []string
	for i := 0; i < len(rest); i++ {
		arg := rest[i]
		switch {
		case arg == "-h" || arg == "--help":
			return nil, ErrHelp
		case arg == "--authflow":
			i++
			if i >= len(rest) {
				return nil, errors.New("--authflow requires a value")
			}
			a.Authflow = rest[i]
		case strings.HasPrefix(arg, "--authflow="):
			a.Authflow = strings.TrimPrefix(arg, "--authflow=")
		case boolFlags[arg] != nil:
			*boolFlags[arg] = true
		case strings.HasPrefix(arg, "-") && arg != "-":
			return nil, fmt.Errorf("unknown flag: %s", arg)
		default:
			positional = append(positional, arg)
		}
	}

	switch a.Command {
	case CmdListAccounts:
		if len(positional) != 0 {
			return nil, fmt.Errorf("list-accounts does not take an account argument (got %v)", positional)
		}
		return a, nil
	case CmdDaemon:
		if len(positional) != 0 {
			return nil, fmt.Errorf("daemon does not take an account argument (got %v); it checks every configured account", positional)
		}
		return a, nil
	case CmdStatus, CmdRefresh:
		// account is optional for status/refresh: no argument means "all
		// accounts".
		if len(positional) > 1 {
			return nil, fmt.Errorf("unexpected extra arguments: %v", positional[1:])
		}
		if len(positional) == 1 {
			a.Account = positional[0]
		}
		return a, nil
	case CmdCompletion:
		if len(positional) == 0 {
			return nil, errors.New("missing required argument: shell (bash or zsh)")
		}
		if len(positional) > 1 {
			return nil, fmt.Errorf("unexpected extra arguments: %v", positional[1:])
		}
		switch positional[0] {
		case "bash", "zsh":
			a.Shell = positional[0]
		default:
			return nil, fmt.Errorf("unsupported shell %q (want \"bash\" or \"zsh\")", positional[0])
		}
		return a, nil
	default:
		if len(positional) == 0 {
			return nil, errors.New("missing required argument: account")
		}
		if len(positional) > 1 {
			return nil, fmt.Errorf("unexpected extra arguments: %v", positional[1:])
		}
		a.Account = positional[0]
		return a, nil
	}
}

const usageText = `usage: omt [-h] [-v] [-d] [-a] [--authflow AUTHFLOW] [-t] account
       omt authorize [-h] [-v] [-d] [--authflow AUTHFLOW] account
       omt refresh [-h] [-v] [-d] [account]
       omt list-accounts
       omt status [-h] [account]
       omt token account
       omt completion bash|zsh
       omt daemon [-h] [-d]

This program obtains and prints a valid OAuth2 access token. State is
maintained in the OS keyring.

commands:
  (none)                run with just an account name to print a valid
                         access token, transparently authorizing (if no
                         token exists yet) or refreshing (if the access
                         token expired) as needed - this is what mutt calls
  authorize              shorthand for "--authorize": always (re-)run the
                         interactive authorization flow for account
  refresh                force a refresh-token exchange, regardless of
                         whether the current access token is still valid,
                         for account if given, or for every configured
                         account that has a refresh token stored if not
                         (accounts with no token yet, or none stored, are
                         skipped rather than treated as errors)
  list-accounts          print the account names configured in config.yaml,
                         one per line
  status                 print authorization status (authorized?, access
                         token valid?, expiration, refresh token present?
                         and its own expiration if known) for every
                         configured account, or just one if given
  token                  print *only* the currently stored access token for
                         account, straight from the keyring - no
                         authorizing, no refreshing, nothing else on
                         stdout, so it can be embedded in a command
                         substitution and passed to another program; fails
                         if account was never authorized
  completion             print a shell completion script for bash or zsh
                         to stdout (see README for how to load it)
  daemon                 run in the foreground, checking every configured
                         account on a timer (global.daemon.interval in
                         config.yaml, default 5m) and refreshing any access
                         token that will expire within the next 5 minutes;
                         prints every refresh and error unconditionally, and
                         (with global.debug: true, or -d/--debug) also
                         prints each check it performs; runs until
                         interrupted (Ctrl-C/SIGTERM)

positional arguments:
  account               account name (not used by list-accounts/completion/
                         daemon; optional for refresh/status, where
                         omitting it means "all accounts"; mandatory for
                         token)

options:
  -h, --help            show this help message and exit
  -v, --verbose         increase verbosity
  -d, --debug           enable debug output
  -a, --authorize       manually authorize new tokens (same as the
                         "authorize" command; kept for backwards
                         compatibility)
  --authflow AUTHFLOW   authcode | localhostauthcode | devicecode
  -t, --test            test IMAP/POP/SMTP endpoints (not yet implemented)
`
