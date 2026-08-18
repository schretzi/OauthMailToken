// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

package cli

import (
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/schretzi/oauthmailtoken/internal/token"
)

// timestampLayout is how stored expirations are rendered in the "status"
// table: local time, second precision, no timezone suffix.
const timestampLayout = "2006-01-02 15:04:05"

// Values printed in the "status" command's STATUS column.
const (
	statusError         = "error"
	statusNotAuthorized = "not authorized"
	statusUnknown       = "unknown"
	statusValid         = "valid"
	statusExpired       = "expired"
)

// Values printed in the EXPIRES / REFRESH TOKEN columns.
const (
	valueNone              = "-"
	valueYes               = "yes"
	valueNo                = "no"
	valueUnknown           = "unknown"
	valueInvalidExpiration = "invalid expiration"
)

// newListAccountsCmd builds the "list-accounts" subcommand.
func newListAccountsCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "list-accounts",
		Short: "Print the account names configured in config.yaml, one per line",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(*cobra.Command, []string) error {
			return a.runListAccounts()
		},
	}
}

func (a *app) runListAccounts() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	for _, name := range accountNames(cfg) {
		a.outln(name)
	}
	return nil
}

// newStatusCmd builds the "status" subcommand.
func newStatusCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "status [account]",
		Short: "Show authorization status for all accounts, or one",
		Long: `Print a table showing, per account: whether it has been authorized, whether
its access token is still valid and when it expires, whether a refresh token
is stored, and that refresh token's own expiry if the provider reported one
(most do not).

A keyring problem on one account is reported in its row rather than failing
the whole command.`,

		Args:              usageArgs(cobra.MaximumNArgs(1)),
		ValidArgsFunction: completeAccounts,

		RunE: func(_ *cobra.Command, args []string) error {
			account := ""
			if len(args) == 1 {
				account = args[0]
			}
			return a.runStatus(account)
		},
	}
}

func (a *app) runStatus(account string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	names := accountNames(cfg)
	if account != "" {
		if _, ok := cfg.Accounts[account]; !ok {
			return errUnknownAccount
		}
		names = []string{account}
	}

	tw := tabwriter.NewWriter(a.out, 0, 0, 2, ' ', 0)
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
		return statusError, loadErr.Error(), valueNone, valueNone
	}
	if tok == nil {
		return statusNotAuthorized, valueNone, valueNone, valueNone
	}

	if tok.RefreshToken == "" {
		refreshToken = valueNo
		refreshExpires = valueNone
	} else {
		refreshToken = valueYes
		refreshExpires = formatExpiration(tok.RefreshTokenExpiration)
	}

	if tok.AccessTokenExpiration == "" {
		return statusUnknown, valueNone, refreshToken, refreshExpires
	}
	exp, err := token.ParseTime(tok.AccessTokenExpiration)
	if err != nil {
		return statusUnknown, valueInvalidExpiration, refreshToken, refreshExpires
	}

	if tok.IsValid() {
		return statusValid, formatRelativeTime(exp), refreshToken, refreshExpires
	}
	return statusExpired, formatRelativeTime(exp), refreshToken, refreshExpires
}

// formatExpiration renders an optional ISO8601 expiration timestamp for
// display: "unknown" if raw is empty (the provider never reported one -
// true for most refresh tokens, since Google/Microsoft don't send an
// expiry for them), "invalid expiration" if unparseable, else the same
// "<local time> (in Ns)" / "<local time> (Ns ago)" form used elsewhere.
func formatExpiration(raw string) string {
	if raw == "" {
		return valueUnknown
	}
	exp, err := token.ParseTime(raw)
	if err != nil {
		return valueInvalidExpiration
	}
	return formatRelativeTime(exp)
}

// formatRelativeTime renders ts as "<local time> (in 41m45s)" if it is in
// the future, or "<local time> (41m45s ago)" if it has already passed.
func formatRelativeTime(ts time.Time) string {
	local := ts.Local().Format(timestampLayout)
	if time.Now().Before(ts) {
		return fmt.Sprintf("%s (in %s)", local, formatDuration(time.Until(ts)))
	}
	return fmt.Sprintf("%s (%s ago)", local, formatDuration(time.Since(ts)))
}

// formatDuration renders d as a rounded-to-the-second, always-positive
// duration string (e.g. "41m45s").
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	return d.Round(time.Second).String()
}
