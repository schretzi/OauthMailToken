// Command omt obtains and prints a valid OAuth2 access token for use by
// mutt (or any other tool that wants an OAuth2 bearer token for IMAP, POP or
// SMTP). It is a Go port of the original Python "Mutt OAuth2 token
// management" script, storing state in the OS keyring instead of an
// encrypted token file.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/schretzi/oauthmailtoken/internal/browser"
	"github.com/schretzi/oauthmailtoken/internal/config"
	"github.com/schretzi/oauthmailtoken/internal/oauth"
	"github.com/schretzi/oauthmailtoken/internal/token"
)

func main() {
	args, err := parseArgs(os.Args[1:])
	if err != nil {
		if errors.Is(err, ErrHelp) {
			fmt.Print(usageText)
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}

	if err := run(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run dispatches to the handler for args.Command.
func run(args *Args) error {
	switch args.Command {
	case CmdListAccounts:
		return runListAccountsCommand()
	case CmdStatus:
		return runStatusCommand(args)
	case CmdAuthorize:
		return runAuthorizeCommand(args)
	case CmdRefresh:
		return runRefreshCommand(args)
	case CmdToken:
		return runTokenCommand(args)
	case CmdCompletion:
		return runCompletionCommand(args)
	case CmdDaemon:
		return runDaemonCommand(args)
	default:
		return runGetCommand(args)
	}
}

// loadConfigAndAccount loads config.yaml and validates that account is
// defined in it, returning the loaded config and that account's settings.
func loadConfigAndAccount(account string) (*config.Config, config.AccountConfig, error) {
	cfgPath, err := config.LocateConfigFile("omt")
	if err != nil {
		return nil, config.AccountConfig{}, fmt.Errorf("locating config: %w", err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, config.AccountConfig{}, fmt.Errorf("loading config: %w", err)
	}
	if cfg.Global == nil {
		return nil, config.AccountConfig{}, errors.New("global section does not exist in config")
	}
	if cfg.Accounts == nil {
		return nil, config.AccountConfig{}, errors.New("accounts section does not exist in config")
	}
	acc, ok := cfg.Accounts[account]
	if !ok {
		return nil, config.AccountConfig{}, errors.New("account does not exist in configfile")
	}
	return cfg, acc, nil
}

// newHTTPClient builds the HTTP client used for all token endpoint/device
// code requests, wiring up response-body debug logging when requested.
func newHTTPClient(args *Args) *http.Client {
	client := &http.Client{Timeout: 30 * time.Second}
	if args.Debug {
		client.Transport = debugTransport{rt: http.DefaultTransport}
	}
	return client
}

// printAccessToken prints tok's access token, matching the Python
// implementation's output (a bare "Access Token: " prefix only in verbose
// mode).
func printAccessToken(tok *token.Token, verbose bool) {
	if verbose {
		fmt.Print("Access Token: ")
	}
	fmt.Println(tok.AccessToken)
}

// exchangeRefresh performs the refresh-token grant exchange for account,
// producing the (multi-line) error messages both refreshAccessToken and
// refreshAccessTokenSilent return on failure.
func exchangeRefresh(client *http.Client, cfg *config.Config, account string, tok *token.Token) (oauth.TokenResponse, error) {
	if tok.RefreshToken == "" {
		return oauth.TokenResponse{}, errors.New(`ERROR: No refresh token. Run "omt authorize <account>" first.`)
	}
	provider, err := cfg.Provider(account)
	if err != nil {
		return oauth.TokenResponse{}, err
	}
	tr, err := oauth.ExchangeRefreshToken(client, provider, tok.RefreshToken)
	if err != nil {
		base := wrapAPIError(err)
		return oauth.TokenResponse{}, fmt.Errorf("%w\nPerhaps refresh token invalid. Try running \"omt authorize %s\"", base, account)
	}
	return tr, nil
}

// refreshAccessToken exchanges tok's refresh token for a new access token
// and persists the result, regardless of whether tok's current access token
// is still valid. It also prints the NOTICE/refresh-token lines the
// single-account commands (get/authorize/refresh <account>) have always
// printed.
func refreshAccessToken(client *http.Client, cfg *config.Config, account string, tok *token.Token, verbose bool) error {
	tr, err := exchangeRefresh(client, cfg, account, tok)
	if err != nil {
		return err
	}
	return updateTokens(tok, tr, account, verbose)
}

// refreshAccessTokenSilent is like refreshAccessToken, but persists the
// result without printing anything - used by "refresh" with no account
// given, which prints its own per-account summary table instead of dumping
// every account's refresh token to stdout.
func refreshAccessTokenSilent(client *http.Client, cfg *config.Config, account string, tok *token.Token) error {
	tr, err := exchangeRefresh(client, cfg, account, tok)
	if err != nil {
		return err
	}
	return storeUpdatedToken(tok, tr, account)
}

// runGetCommand implements the default (no subcommand) behaviour: print a
// valid access token, transparently authorizing (if no token exists yet) or
// refreshing (if the access token expired) as needed. This is what mutt
// calls, so its behaviour (including the "--authorize"/"-a" flag) stays
// backwards compatible.
func runGetCommand(args *Args) error {
	cfg, acc, err := loadConfigAndAccount(args.Account)
	if err != nil {
		return err
	}

	tok, err := loadTokenWithDefaultsNotice(cfg, args.Account)
	if err != nil {
		return fmt.Errorf("reading stored token: %w", err)
	}

	client := newHTTPClient(args)

	if tok == nil {
		fmt.Println("Token not found, please authorize")
		tok, err = authorize(client, cfg, &acc, args, tok)
		if err != nil {
			return err
		}
	}

	if args.Authorize {
		fmt.Println("Authorization choosen")
		tok, err = authorize(client, cfg, &acc, args, tok)
		if err != nil {
			return err
		}
	}

	if !tok.IsValid() {
		if args.Verbose {
			fmt.Println("NOTICE: Invalid or expired access token; using refresh token to obtain new access token.")
		}
		if err := refreshAccessToken(client, cfg, args.Account, tok, args.Verbose); err != nil {
			return err
		}
	}

	printAccessToken(tok, args.Verbose)
	return nil
}

// runAuthorizeCommand implements the "authorize" subcommand: a shorthand for
// `omt --authorize <account>` that always (re-)runs the interactive
// authorization flow.
func runAuthorizeCommand(args *Args) error {
	cfg, acc, err := loadConfigAndAccount(args.Account)
	if err != nil {
		return err
	}

	tok, err := loadTokenWithDefaultsNotice(cfg, args.Account)
	if err != nil {
		return fmt.Errorf("reading stored token: %w", err)
	}

	client := newHTTPClient(args)
	tok, err = authorize(client, cfg, &acc, args, tok)
	if err != nil {
		return err
	}

	printAccessToken(tok, args.Verbose)
	return nil
}

// runRefreshCommand implements the "refresh" subcommand: force a
// refresh-token exchange, regardless of whether the current access token is
// still valid, for args.Account if given, or for every configured account
// that has a refresh token stored if not.
func runRefreshCommand(args *Args) error {
	if args.Account != "" {
		return runRefreshSingleAccount(args)
	}
	return runRefreshAllAccounts(args)
}

// runRefreshSingleAccount forces a refresh-token exchange for exactly one
// account. Unlike the default command, it does not fall back to an
// interactive authorization if no token is stored yet.
func runRefreshSingleAccount(args *Args) error {
	cfg, _, err := loadConfigAndAccount(args.Account)
	if err != nil {
		return err
	}

	tok, err := loadTokenWithDefaultsNotice(cfg, args.Account)
	if err != nil {
		return fmt.Errorf("reading stored token: %w", err)
	}
	if tok == nil {
		return fmt.Errorf("no stored token for %q; run \"omt authorize %s\" first", args.Account, args.Account)
	}

	client := newHTTPClient(args)
	if err := refreshAccessToken(client, cfg, args.Account, tok, args.Verbose); err != nil {
		return err
	}

	printAccessToken(tok, args.Verbose)
	return nil
}

// runTokenCommand implements the "token" subcommand: print *only* the
// currently stored access token for args.Account, straight from the
// keyring, with nothing else on stdout - so it can be safely embedded in a
// command substitution and passed to another program, e.g.
// `curl -H "Authorization: Bearer $(omt token me@gmail.com)" ...`. Unlike
// the default "get" command, it never authorizes or refreshes: it's a
// read-only lookup of whatever is currently stored, and fails if there's
// nothing there. If the stored token happens to be expired, that's reported
// as a warning on stderr (not stdout), and the token is printed anyway -
// the caller asked for what's stored, and stderr doesn't interfere with
// piping stdout elsewhere.
func runTokenCommand(args *Args) error {
	if _, _, err := loadConfigAndAccount(args.Account); err != nil {
		return err
	}

	// Deliberately not loadTokenWithDefaultsNotice: that prints informational
	// notices to stdout on a freshly-defaulted config, which would pollute
	// the output this command promises to keep to just the token.
	tok, err := token.Load(args.Account)
	if err != nil {
		return fmt.Errorf("reading stored token: %w", err)
	}
	if tok == nil || tok.AccessToken == "" {
		return fmt.Errorf("no stored token for %q; run \"omt authorize %s\" first", args.Account, args.Account)
	}
	if !tok.IsValid() {
		fmt.Fprintf(os.Stderr, "WARNING: stored token for %q is expired; run \"omt refresh %s\" (or \"omt authorize %s\" if that fails).\n", args.Account, args.Account, args.Account)
	}

	fmt.Println(tok.AccessToken)
	return nil
}

// runRefreshAllAccounts forces a refresh-token exchange for every configured
// account that currently has a refresh token stored. Accounts with no token
// at all, or a token with no refresh token, are skipped rather than treated
// as errors - refreshing "all which are possible" is the point. Prints a
// one-line-per-account summary table, and returns an error (causing a
// non-zero exit) if at least one attempted refresh actually failed.
func runRefreshAllAccounts(args *Args) error {
	cfgPath, err := config.LocateConfigFile("omt")
	if err != nil {
		return fmt.Errorf("locating config: %w", err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if cfg.Global == nil {
		return errors.New("global section does not exist in config")
	}
	if cfg.Accounts == nil {
		return errors.New("accounts section does not exist in config")
	}

	names := make([]string, 0, len(cfg.Accounts))
	for name := range cfg.Accounts {
		names = append(names, name)
	}
	sort.Strings(names)

	client := newHTTPClient(args)
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ACCOUNT\tRESULT")

	failed := false
	for _, name := range names {
		tok, loadErr := loadTokenWithDefaultsNotice(cfg, name)
		switch {
		case loadErr != nil:
			fmt.Fprintf(tw, "%s\terror: %s\n", name, oneLine(loadErr))
			failed = true
		case tok == nil:
			fmt.Fprintf(tw, "%s\tskipped: not authorized yet\n", name)
		case tok.RefreshToken == "":
			fmt.Fprintf(tw, "%s\tskipped: no refresh token (run \"omt authorize %s\")\n", name, name)
		default:
			if err := refreshAccessTokenSilent(client, cfg, name, tok); err != nil {
				fmt.Fprintf(tw, "%s\terror: %s\n", name, oneLine(err))
				failed = true
			} else {
				fmt.Fprintf(tw, "%s\trefreshed (valid until %s)\n", name, tok.AccessTokenExpiration)
			}
		}
	}
	if flushErr := tw.Flush(); flushErr != nil {
		return flushErr
	}
	if failed {
		return errors.New("one or more accounts failed to refresh")
	}
	return nil
}

// oneLine collapses a (possibly multi-line) error message into one line so
// it doesn't break tabwriter's column alignment.
func oneLine(err error) string {
	return strings.ReplaceAll(err.Error(), "\n", "; ")
}

// daemonExpiryLookahead is how far ahead of an access token's expiration the
// daemon proactively refreshes it, so a token doesn't go stale in the gap
// between two ticks - notably the gap right after the machine wakes from
// sleep, before the next tick fires.
const daemonExpiryLookahead = 5 * time.Minute

// defaultDaemonInterval is used when global.daemon.interval isn't set in
// config.yaml.
const defaultDaemonInterval = 5 * time.Minute

// runDaemonCommand implements the "daemon" subcommand: a long-running
// process that periodically checks every configured account's stored access
// token and refreshes any that will expire within daemonExpiryLookahead.
// This exists because an external timer (e.g. launchd's StartInterval) does
// not fire while the machine is asleep and does not catch up missed ticks -
// only fires once, some time after wake - which can leave tokens expired
// for a while. The daemon checks expiry itself on every tick instead of
// relying solely on ticking at the right moment. It runs until interrupted
// (SIGINT/SIGTERM).
func runDaemonCommand(args *Args) error {
	cfgPath, err := config.LocateConfigFile("omt")
	if err != nil {
		return fmt.Errorf("locating config: %w", err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if cfg.Global == nil {
		return errors.New("global section does not exist in config")
	}
	if cfg.Accounts == nil {
		return errors.New("accounts section does not exist in config")
	}

	interval, err := daemonInterval(cfg)
	if err != nil {
		return err
	}
	debug := args.Debug || cfg.Global.Debug

	names := make([]string, 0, len(cfg.Accounts))
	for name := range cfg.Accounts {
		names = append(names, name)
	}
	sort.Strings(names)

	client := newHTTPClient(args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("omt daemon: starting, checking %d account(s) every %s, refreshing tokens expiring within %s\n", len(names), interval, daemonExpiryLookahead)

	daemonTick(client, cfg, names, debug)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			fmt.Println("omt daemon: received shutdown signal, exiting")
			return nil
		case <-ticker.C:
			daemonTick(client, cfg, names, debug)
		}
	}
}

// daemonInterval resolves the configured daemon check interval, defaulting
// to defaultDaemonInterval (and printing a NOTICE, matching the same
// default-and-explain pattern used elsewhere for unset config) if
// global.daemon.interval isn't set.
func daemonInterval(cfg *config.Config) (time.Duration, error) {
	if cfg.Global.Daemon == nil || cfg.Global.Daemon.Interval == "" {
		fmt.Printf("NOTICE: global.daemon.interval not set in config, defaulting to %s\n", defaultDaemonInterval)
		return defaultDaemonInterval, nil
	}
	d, err := time.ParseDuration(cfg.Global.Daemon.Interval)
	if err != nil {
		return 0, fmt.Errorf("parsing global.daemon.interval %q: %w", cfg.Global.Daemon.Interval, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("global.daemon.interval must be positive, got %q", cfg.Global.Daemon.Interval)
	}
	return d, nil
}

// daemonTick checks every account in names once, refreshing any whose
// stored access token will expire within daemonExpiryLookahead. It always
// prints errors and successful refreshes; with debug enabled it also prints
// a start/end banner for the tick and one line per account explaining what
// it found and decided.
func daemonTick(client *http.Client, cfg *config.Config, names []string, debug bool) {
	if debug {
		fmt.Printf("[%s] omt daemon: tick start, checking %d account(s)\n", time.Now().Format(time.RFC3339), len(names))
	}
	for _, name := range names {
		daemonCheckAccount(client, cfg, name, debug)
	}
	if debug {
		fmt.Printf("[%s] omt daemon: tick done\n", time.Now().Format(time.RFC3339))
	}
}

// daemonCheckAccount checks (and refreshes if needed) the stored token for
// one account, as part of a daemonTick. Reading/keyring errors and refresh
// failures are always printed (prefixed "ERROR:"); "nothing to do" states
// (not authorized yet, no refresh token, not due yet) are only printed when
// debug is enabled.
func daemonCheckAccount(client *http.Client, cfg *config.Config, name string, debug bool) {
	ts := time.Now().Format(time.RFC3339)

	tok, err := token.Load(name)
	if err != nil {
		fmt.Printf("[%s] ERROR: omt daemon: reading stored token for %q: %v\n", ts, name, err)
		return
	}
	if tok == nil {
		if debug {
			fmt.Printf("[%s] omt daemon: %s: not authorized yet, skipping\n", ts, name)
		}
		return
	}
	if tok.RefreshToken == "" {
		if debug {
			fmt.Printf("[%s] omt daemon: %s: no refresh token stored, skipping\n", ts, name)
		}
		return
	}

	due, reason := daemonRefreshDue(tok)
	if !due {
		if debug {
			fmt.Printf("[%s] omt daemon: %s: %s, no refresh needed\n", ts, name, reason)
		}
		return
	}
	if debug {
		fmt.Printf("[%s] omt daemon: %s: %s, refreshing\n", ts, name, reason)
	}

	if err := refreshAccessTokenSilent(client, cfg, name, tok); err != nil {
		fmt.Printf("[%s] ERROR: omt daemon: refreshing %q: %s\n", ts, name, oneLine(err))
		return
	}
	fmt.Printf("[%s] omt daemon: refreshed %s (valid until %s)\n", ts, name, tok.AccessTokenExpiration)
}

// daemonRefreshDue reports whether tok's access token needs refreshing now:
// either it has no usable stored expiration (no access token, no/invalid
// expiration timestamp), or it expires within daemonExpiryLookahead. reason
// is a human-readable explanation suitable for debug logging either way.
func daemonRefreshDue(tok *token.Token) (due bool, reason string) {
	if tok.AccessToken == "" || tok.AccessTokenExpiration == "" {
		return true, "no access token stored"
	}
	exp, err := token.ParseTime(tok.AccessTokenExpiration)
	if err != nil {
		return true, fmt.Sprintf("invalid stored expiration %q", tok.AccessTokenExpiration)
	}
	remaining := time.Until(exp)
	if remaining <= daemonExpiryLookahead {
		return true, fmt.Sprintf("access token expires in %s (within %s lookahead)", formatDuration(remaining), daemonExpiryLookahead)
	}
	return false, fmt.Sprintf("access token valid for %s", formatDuration(remaining))
}

// runListAccountsCommand implements the "list-accounts" subcommand: print
// the account names configured in config.yaml, one per line, sorted.
func runListAccountsCommand() error {
	cfgPath, err := config.LocateConfigFile("omt")
	if err != nil {
		return fmt.Errorf("locating config: %w", err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if cfg.Accounts == nil {
		return errors.New("accounts section does not exist in config")
	}

	names := make([]string, 0, len(cfg.Accounts))
	for name := range cfg.Accounts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Println(name)
	}
	return nil
}

// runStatusCommand implements the "status" subcommand: print authorization
// status (authorized?, access token valid?, expiration, refresh token
// present?) for every configured account, or just args.Account if given.
func runStatusCommand(args *Args) error {
	cfgPath, err := config.LocateConfigFile("omt")
	if err != nil {
		return fmt.Errorf("locating config: %w", err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if cfg.Accounts == nil {
		return errors.New("accounts section does not exist in config")
	}

	var names []string
	if args.Account != "" {
		if _, ok := cfg.Accounts[args.Account]; !ok {
			return errors.New("account does not exist in configfile")
		}
		names = []string{args.Account}
	} else {
		names = make([]string, 0, len(cfg.Accounts))
		for name := range cfg.Accounts {
			names = append(names, name)
		}
		sort.Strings(names)
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ACCOUNT\tPROVIDER\tSTATUS\tEXPIRES\tREFRESH TOKEN\tREFRESH EXPIRES")
	for _, name := range names {
		acc := cfg.Accounts[name]
		tok, loadErr := token.Load(name)
		status, expires, refresh, refreshExpires := formatAccountStatus(tok, loadErr)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", name, acc.Provider, status, expires, refresh, refreshExpires)
	}
	return tw.Flush()
}

// formatAccountStatus turns a loaded token (and any error encountered while
// loading it) into the (status, expires, refreshToken, refreshExpires)
// columns printed by the "status" command. It never returns an error
// itself, so one account's keyring problem doesn't prevent showing the
// others.
func formatAccountStatus(tok *token.Token, loadErr error) (status, expires, refreshToken, refreshExpires string) {
	if loadErr != nil {
		return "error", loadErr.Error(), "-", "-"
	}
	if tok == nil {
		return "not authorized", "-", "-", "-"
	}

	if tok.RefreshToken == "" {
		refreshToken = "no"
		refreshExpires = "-"
	} else {
		refreshToken = "yes"
		refreshExpires = formatExpiration(tok.RefreshTokenExpiration)
	}

	if tok.AccessTokenExpiration == "" {
		return "unknown", "-", refreshToken, refreshExpires
	}
	exp, err := token.ParseTime(tok.AccessTokenExpiration)
	if err != nil {
		return "unknown", "invalid expiration", refreshToken, refreshExpires
	}

	if tok.IsValid() {
		return "valid", fmt.Sprintf("%s (in %s)", exp.Local().Format("2006-01-02 15:04:05"), formatDuration(time.Until(exp))), refreshToken, refreshExpires
	}
	return "expired", fmt.Sprintf("%s (%s ago)", exp.Local().Format("2006-01-02 15:04:05"), formatDuration(time.Since(exp))), refreshToken, refreshExpires
}

// formatExpiration renders an optional ISO8601 expiration timestamp for
// display: "unknown" if raw is empty (the provider never reported one -
// true for most refresh tokens, since Google/Microsoft don't send an
// expiry for them), "invalid expiration" if unparseable, else "<local time>
// (in Ns)" or "<local time> (Ns ago)".
func formatExpiration(raw string) string {
	if raw == "" {
		return "unknown"
	}
	exp, err := token.ParseTime(raw)
	if err != nil {
		return "invalid expiration"
	}
	if time.Now().Before(exp) {
		return fmt.Sprintf("%s (in %s)", exp.Local().Format("2006-01-02 15:04:05"), formatDuration(time.Until(exp)))
	}
	return fmt.Sprintf("%s (%s ago)", exp.Local().Format("2006-01-02 15:04:05"), formatDuration(time.Since(exp)))
}

// formatDuration renders d as a rounded-to-the-second, always-positive
// duration string (e.g. "41m45s").
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	return d.Round(time.Second).String()
}

// loadTokenWithDefaultsNotice loads the stored token for account, printing
// the same informational notices as the Python implementation's
// readToken() when the config doesn't specify a storage backend.
func loadTokenWithDefaultsNotice(cfg *config.Config, account string) (*token.Token, error) {
	if cfg.Global.Storage == "" {
		fmt.Println("Storage not set, trying keyring with system backend")
		cfg.Global.Storage = "keyring"
		cfg.Global.KeyringBackend = "system"
	}
	if cfg.Global.Storage == "keyring" && cfg.Global.KeyringBackend == "" {
		fmt.Println("Keyring Backend not set, trying keyring with system backend")
		cfg.Global.KeyringBackend = "system"
	}
	return token.Load(account)
}

// authorize runs the configured (or interactively chosen) OAuth2 flow for
// the account and stores the resulting tokens. current is the
// previously-loaded token, if any (may be nil); its refresh token is
// preserved if the new token response doesn't include one.
func authorize(client *http.Client, cfg *config.Config, acc *config.AccountConfig, args *Args, current *token.Token) (*token.Token, error) {
	provider, err := cfg.Provider(args.Account)
	if err != nil {
		return nil, err
	}

	if acc.Authflow == "" {
		switch {
		case args.Authflow != "":
			acc.Authflow = args.Authflow
		default:
			acc.Authflow = promptLine(`Preferred OAuth2 flow ("authcode" or "localhostauthcode" or "devicecode"): `)
		}
	}

	browserCfg := cfg.EffectiveBrowser(args.Account)

	var tr oauth.TokenResponse
	switch acc.Authflow {
	case "authcode", "localhostauthcode":
		tr, err = runAuthCodeFlow(client, provider, args.Account, acc.Authflow, browserCfg)
	case "devicecode":
		tr, err = runDeviceCodeFlow(client, provider, browserCfg)
	default:
		return nil, fmt.Errorf("ERROR: Unknown OAuth2 flow %q. Delete token file and start over.", acc.Authflow)
	}
	if err != nil {
		return nil, err
	}

	tok := current
	if tok == nil {
		tok = &token.Token{}
	}
	if err := updateTokens(tok, tr, args.Account, args.Verbose); err != nil {
		return nil, err
	}
	return tok, nil
}

// storeUpdatedToken applies a token endpoint response to tok - including any
// refresh-token expiration the provider reported - and persists it to the OS
// keyring, without printing anything.
func storeUpdatedToken(tok *token.Token, tr oauth.TokenResponse, account string) error {
	tok.ApplyResponse(tr.AccessToken, tr.ExpiresInSeconds(), tr.RefreshToken, tr.RefreshExpiresInSeconds())
	if err := token.Store(account, tok); err != nil {
		return fmt.Errorf("storing token in keyring: %w", err)
	}
	return nil
}

// updateTokens is storeUpdatedToken plus the stdout notices the original
// Python implementation printed after obtaining new tokens (a NOTICE line in
// verbose mode, and the refresh token unconditionally) - used by the
// single-account commands (get/authorize/refresh <account>) to stay
// backwards compatible.
func updateTokens(tok *token.Token, tr oauth.TokenResponse, account string, verbose bool) error {
	if err := storeUpdatedToken(tok, tr, account); err != nil {
		return err
	}
	if verbose {
		fmt.Printf("NOTICE: Obtained new access token, expires %s.\n", tok.AccessTokenExpiration)
	}
	fmt.Println(tok.RefreshToken)
	return nil
}

// runAuthCodeFlow runs the "authcode" (manual copy/paste) or
// "localhostauthcode" (local redirect listener) flow and exchanges the
// resulting code for tokens. If browserCfg is non-nil, it also tries to open
// authURL in the configured browser/profile.
func runAuthCodeFlow(client *http.Client, provider config.ProviderConfig, account, mode string, browserCfg *config.BrowserConfig) (oauth.TokenResponse, error) {
	pkce, err := oauth.NewPKCE()
	if err != nil {
		return oauth.TokenResponse{}, err
	}

	redirectURI := provider.RedirectURI
	var ln net.Listener
	if mode == "localhostauthcode" {
		ln, err = oauth.ListenLocal()
		if err != nil {
			return oauth.TokenResponse{}, err
		}
		redirectURI = fmt.Sprintf("http://localhost:%d/", oauth.LocalPort(ln))
	}

	authURL, err := oauth.BuildAuthorizeURL(provider, account, redirectURI, pkce.Challenge)
	if err != nil {
		return oauth.TokenResponse{}, err
	}
	fmt.Println(authURL)
	tryOpenBrowser(browserCfg, authURL)

	var code string
	if mode == "authcode" {
		code = promptLine("Visit displayed URL to retrieve authorization code. Enter code from server (might be in browser address bar): ")
	} else {
		fmt.Print("Visit displayed URL to authorize this application. Waiting...")
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		code, err = oauth.ServeOnce(ctx, ln)
		if err != nil {
			return oauth.TokenResponse{}, wrapAPIError(err)
		}
	}
	if code == "" {
		return oauth.TokenResponse{}, errors.New("did not obtain an authcode")
	}

	fmt.Println("Exchanging the authorization code for an access token")
	tr, err := oauth.ExchangeAuthCode(client, provider, code, pkce.Verifier, redirectURI)
	if err != nil {
		return oauth.TokenResponse{}, wrapAPIError(err)
	}
	return tr, nil
}

// runDeviceCodeFlow runs the OAuth2 device-code flow, printing progress the
// same way the Python implementation does. If browserCfg is non-nil, it also
// tries to open the verification URL in the configured browser/profile.
func runDeviceCodeFlow(client *http.Client, provider config.ProviderConfig, browserCfg *config.BrowserConfig) (oauth.TokenResponse, error) {
	dc, err := oauth.RequestDeviceCode(client, provider)
	if err != nil {
		return oauth.TokenResponse{}, wrapAPIError(err)
	}
	fmt.Println(dc.Message)
	if dc.VerificationURI != "" {
		tryOpenBrowser(browserCfg, dc.VerificationURI)
	}
	fmt.Print("Polling...")

	tr, err := oauth.PollDeviceToken(client, provider, dc, time.Sleep, func() { fmt.Print(".") })
	if err != nil {
		switch {
		case errors.Is(err, oauth.ErrAuthorizationDeclined):
			fmt.Println(" user declined authorization.")
			return oauth.TokenResponse{}, errors.New("authorization declined")
		case errors.Is(err, oauth.ErrDeviceCodeExpired):
			fmt.Println(" too much time has elapsed.")
			return oauth.TokenResponse{}, errors.New("too much time elapsed for device code")
		default:
			return oauth.TokenResponse{}, wrapAPIError(err)
		}
	}
	fmt.Println()
	return tr, nil
}

// wrapAPIError turns an *oauth.APIError into a plain error whose message
// matches the two lines the Python implementation prints (error code, then
// description), so a single fmt.Println at the top level reproduces it.
func wrapAPIError(err error) error {
	var apiErr *oauth.APIError
	if errors.As(err, &apiErr) {
		msg := apiErr.Code
		if apiErr.Description != "" {
			msg += "\n" + apiErr.Description
		}
		return errors.New(msg)
	}
	return err
}

// tryOpenBrowser attempts to open targetURL via cfg's configured browser
// command (see internal/browser). It never fails the calling flow: cfg may
// be nil (no browser configured - a no-op), and any launch error is only
// printed as a notice, since the URL was already printed for the user to
// open manually.
func tryOpenBrowser(cfg *config.BrowserConfig, targetURL string) {
	if err := browser.Open(cfg, targetURL); err != nil {
		fmt.Printf("NOTICE: could not launch configured browser (%v); open the URL above manually.\n", err)
	}
}

func promptLine(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}
