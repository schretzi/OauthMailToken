// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/schretzi/oauthmailtoken/internal/config"
	"github.com/schretzi/oauthmailtoken/internal/oauth"
	"github.com/schretzi/oauthmailtoken/internal/token"
)

// newRefreshCmd builds the "refresh" subcommand: force a refresh-token
// exchange regardless of whether the current access token is still valid,
// for one account or for all of them.
func newRefreshCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "refresh [account]",
		Short: "Force a refresh-token exchange, even if the access token is still valid",
		Long: `Exchange the stored refresh token for a new access token, whether or not the
current one has expired.

With no account, every configured account that has a refresh token stored is
refreshed and a one-line-per-account summary is printed. Accounts that were
never authorized, or that have no refresh token, are skipped rather than
treated as errors; the command still exits non-zero if an attempted refresh
actually failed.`,

		Args:              usageArgs(cobra.MaximumNArgs(1)),
		ValidArgsFunction: completeAccounts,

		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				return a.runRefreshOne(cmd.Context(), args[0])
			}
			return a.runRefreshAll(cmd.Context())
		},
	}
}

// runRefreshOne forces a refresh-token exchange for exactly one account.
// Unlike the root command, it does not fall back to an interactive
// authorization if no token is stored yet.
func (a *app) runRefreshOne(ctx context.Context, account string) error {
	cfg, _, err := loadConfigAndAccount(account)
	if err != nil {
		return err
	}

	tok, err := a.loadTokenWithDefaultsNotice(cfg, account)
	if err != nil {
		return fmt.Errorf("reading stored token: %w", err)
	}
	if tok == nil {
		return fmt.Errorf("no stored token for %q; run %q first", account, "omt authorize "+account)
	}

	if err := a.refreshAccessToken(ctx, a.httpClient(), cfg, account, tok); err != nil {
		return err
	}

	a.printAccessToken(tok)
	return nil
}

// runRefreshAll refreshes every configured account that currently has a
// refresh token stored, printing a summary table.
func (a *app) runRefreshAll(ctx context.Context) error {
	cfg, err := loadConfigWithProviders()
	if err != nil {
		return err
	}

	client := a.httpClient()
	tw := tabwriter.NewWriter(a.out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ACCOUNT\tRESULT")

	failed := false
	for _, name := range accountNames(cfg) {
		tok, loadErr := a.loadTokenWithDefaultsNotice(cfg, name)
		switch {
		case loadErr != nil:
			fmt.Fprintf(tw, "%s\terror: %s\n", name, oneLine(loadErr))
			failed = true
		case tok == nil:
			fmt.Fprintf(tw, "%s\tskipped: not authorized yet\n", name)
		case tok.RefreshToken == "":
			fmt.Fprintf(tw, "%s\tskipped: no refresh token (run \"omt authorize %s\")\n", name, name)
		default:
			if err := a.refreshAccessTokenSilent(ctx, client, cfg, name, tok); err != nil {
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

// exchangeRefresh performs the refresh-token grant exchange for account,
// producing the (multi-line) error messages both refreshAccessToken and
// refreshAccessTokenSilent return on failure.
func exchangeRefresh(ctx context.Context, client *http.Client, cfg *config.Config, account string, tok *token.Token) (oauth.TokenResponse, error) {
	if tok.RefreshToken == "" {
		return oauth.TokenResponse{}, errors.New(`no refresh token stored; run "omt authorize <account>" first`)
	}
	provider, err := cfg.Provider(account)
	if err != nil {
		return oauth.TokenResponse{}, err
	}
	tr, err := oauth.ExchangeRefreshToken(ctx, client, provider, tok.RefreshToken)
	if err != nil {
		base := wrapAPIError(err)
		return oauth.TokenResponse{}, fmt.Errorf("%w\nPerhaps refresh token invalid. Try running \"omt authorize %s\"", base, account)
	}
	return tr, nil
}

// refreshAccessToken exchanges tok's refresh token for a new access token
// and persists the result, printing the notices the single-account commands
// have always printed.
func (a *app) refreshAccessToken(ctx context.Context, client *http.Client, cfg *config.Config, account string, tok *token.Token) error {
	tr, err := exchangeRefresh(ctx, client, cfg, account, tok)
	if err != nil {
		return err
	}
	return a.updateTokens(tok, tr, account)
}

// refreshAccessTokenSilent is like refreshAccessToken, but persists the
// result without printing anything - used by "refresh" with no account
// given, which prints its own per-account summary table instead.
func (a *app) refreshAccessTokenSilent(ctx context.Context, client *http.Client, cfg *config.Config, account string, tok *token.Token) error {
	tr, err := exchangeRefresh(ctx, client, cfg, account, tok)
	if err != nil {
		return err
	}
	return storeUpdatedToken(tok, tr, account)
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

// updateTokens is storeUpdatedToken plus the notices printed after obtaining
// new tokens.
//
// The Python implementation printed the refresh token unconditionally; here
// it is behind -v/--verbose. A refresh token is a long-lived credential -
// possession of it is enough to mint access tokens until it is revoked - so
// echoing it into the terminal scrollback (and any log capturing stderr) on
// every single authorize/refresh is a needless exposure. Ask for it with -v
// when you actually want to see it.
func (a *app) updateTokens(tok *token.Token, tr oauth.TokenResponse, account string) error {
	if err := storeUpdatedToken(tok, tr, account); err != nil {
		return err
	}
	if a.verbose {
		a.infof("NOTICE: Obtained new access token, expires %s.\n", tok.AccessTokenExpiration)
		a.infof("Refresh token: %s\n", tok.RefreshToken)
	}
	return nil
}
