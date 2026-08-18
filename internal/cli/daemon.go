// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

package cli

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/schretzi/oauthmailtoken/internal/config"
	"github.com/schretzi/oauthmailtoken/internal/token"
)

// daemonExpiryLookahead is how far ahead of an access token's expiration the
// daemon proactively refreshes it, so a token doesn't go stale in the gap
// between two ticks - notably the gap right after the machine wakes from
// sleep, before the next tick fires.
const daemonExpiryLookahead = 5 * time.Minute

// defaultDaemonInterval is used when global.daemon.interval isn't set in
// config.yaml.
const defaultDaemonInterval = 5 * time.Minute

// newDaemonCmd builds the "daemon" subcommand.
func newDaemonCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "daemon",
		Short: "Run in the foreground, periodically refreshing tokens due to expire",
		Long: `Check every configured account on a timer (global.daemon.interval in
config.yaml, default 5m) and refresh any access token that will expire
within the next 5 minutes. Runs until interrupted (Ctrl-C/SIGTERM).

This exists because an external timer (cron, launchd's StartInterval) does
not fire while the machine is asleep and does not catch up missed ticks - it
fires once, some time after wake - which can leave tokens expired for a
while. The daemon checks expiry itself on every tick rather than relying on
ticking at exactly the right moment.

Refreshes and errors are always printed; with global.debug: true (or
-d/--debug) each individual check is printed too.`,

		Args: usageArgs(cobra.NoArgs),

		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.runDaemon(cmd.Context())
		},
	}
}

func (a *app) runDaemon(ctx context.Context) error {
	cfg, err := loadConfigWithProviders()
	if err != nil {
		return err
	}

	interval, err := a.daemonInterval(cfg)
	if err != nil {
		return err
	}
	debug := a.debug || cfg.Global.Debug
	names := accountNames(cfg)
	client := a.httpClient()

	a.outf("omt daemon: starting, checking %d account(s) every %s, refreshing tokens expiring within %s\n", len(names), interval, daemonExpiryLookahead)

	a.daemonTick(ctx, client, cfg, names, debug)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			a.outln("omt daemon: received shutdown signal, exiting")
			return nil
		case <-ticker.C:
			a.daemonTick(ctx, client, cfg, names, debug)
		}
	}
}

// daemonInterval resolves the configured daemon check interval, defaulting
// to defaultDaemonInterval (and printing a NOTICE, matching the same
// default-and-explain pattern used elsewhere for unset config) if
// global.daemon.interval isn't set.
func (a *app) daemonInterval(cfg *config.Config) (time.Duration, error) {
	if cfg.Global.Daemon == nil || cfg.Global.Daemon.Interval == "" {
		a.outf("NOTICE: global.daemon.interval not set in config, defaulting to %s\n", defaultDaemonInterval)
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
//
// Unlike the interactive commands, the daemon writes its log to the result
// stream: the log *is* this command's output, and it is what a launchd
// StandardOutPath or a systemd unit captures.
func (a *app) daemonTick(ctx context.Context, client *http.Client, cfg *config.Config, names []string, debug bool) {
	if debug {
		a.outf("[%s] omt daemon: tick start, checking %d account(s)\n", time.Now().Format(time.RFC3339), len(names))
	}
	for _, name := range names {
		a.daemonCheckAccount(ctx, client, cfg, name, debug)
	}
	if debug {
		a.outf("[%s] omt daemon: tick done\n", time.Now().Format(time.RFC3339))
	}
}

// daemonCheckAccount checks (and refreshes if needed) the stored token for
// one account, as part of a daemonTick. Reading/keyring errors and refresh
// failures are always printed (prefixed "ERROR:"); "nothing to do" states
// (not authorized yet, no refresh token, not due yet) are only printed when
// debug is enabled.
func (a *app) daemonCheckAccount(ctx context.Context, client *http.Client, cfg *config.Config, name string, debug bool) {
	ts := time.Now().Format(time.RFC3339)

	tok, err := token.Load(name)
	if err != nil {
		a.outf("[%s] ERROR: omt daemon: reading stored token for %q: %v\n", ts, name, err)
		return
	}
	if tok == nil {
		if debug {
			a.outf("[%s] omt daemon: %s: not authorized yet, skipping\n", ts, name)
		}
		return
	}
	if tok.RefreshToken == "" {
		if debug {
			a.outf("[%s] omt daemon: %s: no refresh token stored, skipping\n", ts, name)
		}
		return
	}

	due, reason := daemonRefreshDue(tok)
	if !due {
		if debug {
			a.outf("[%s] omt daemon: %s: %s, no refresh needed\n", ts, name, reason)
		}
		return
	}
	if debug {
		a.outf("[%s] omt daemon: %s: %s, refreshing\n", ts, name, reason)
	}

	if err := a.refreshAccessTokenSilent(ctx, client, cfg, name, tok); err != nil {
		a.outf("[%s] ERROR: omt daemon: refreshing %q: %s\n", ts, name, oneLine(err))
		return
	}
	a.outf("[%s] omt daemon: refreshed %s (valid until %s)\n", ts, name, tok.AccessTokenExpiration)
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
	return false, "access token valid for " + formatDuration(remaining)
}
