// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/schretzi/oauthmailtoken/internal/config"
	"github.com/schretzi/oauthmailtoken/internal/oauth"
	"github.com/schretzi/oauthmailtoken/internal/token"
)

// authflowFlagUsage is shared by the root and authorize commands so the two
// descriptions cannot drift apart.
const authflowFlagUsage = "OAuth2 flow to use for a first-time authorization: " +
	config.AuthflowAuthCode + " | " + config.AuthflowLocalhostAuthCode + " | " + config.AuthflowDeviceCode

// authflows are the accepted --authflow values, in the order they are
// offered for shell completion.
var authflows = []string{
	config.AuthflowLocalhostAuthCode,
	config.AuthflowAuthCode,
	config.AuthflowDeviceCode,
}

// registerAuthflowCompletion makes the shell offer the valid --authflow
// values instead of falling back to filename completion.
func registerAuthflowCompletion(cmd *cobra.Command) {
	_ = cmd.RegisterFlagCompletionFunc("authflow",
		func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
			return authflows, cobra.ShellCompDirectiveNoFileComp
		})
}

// newAuthorizeCmd builds the "authorize" subcommand: always (re-)run the
// interactive authorization flow for an account.
func newAuthorizeCmd(a *app) *cobra.Command {
	var authflow string

	cmd := &cobra.Command{
		Use:   "authorize <account>",
		Short: "Re-run the interactive authorization flow for an account",
		Long: `Run the interactive OAuth2 authorization flow for the account and store the
resulting tokens, whether or not a valid token already exists.

Which flow is used comes from the account's "authflow" setting in
config.yaml, or from --authflow, or - if neither is set - from an
interactive prompt.`,

		Args:              usageArgs(cobra.ExactArgs(1)),
		ValidArgsFunction: completeAccounts,

		RunE: func(cmd *cobra.Command, args []string) error {
			return a.runAuthorize(cmd.Context(), args[0], authflow)
		},
	}

	cmd.Flags().StringVar(&authflow, "authflow", "", authflowFlagUsage)
	registerAuthflowCompletion(cmd)

	return cmd
}

func (a *app) runAuthorize(ctx context.Context, account, authflow string) error {
	cfg, acc, err := loadConfigAndAccount(account)
	if err != nil {
		return err
	}

	tok, err := a.loadTokenWithDefaultsNotice(cfg, account)
	if err != nil {
		return fmt.Errorf("reading stored token: %w", err)
	}

	tok, err = a.authorize(ctx, a.httpClient(), cfg, &acc, account, authflow, tok)
	if err != nil {
		return err
	}

	a.printAccessToken(tok)
	return nil
}

// authorize runs the configured (or interactively chosen) OAuth2 flow for
// the account and stores the resulting tokens. current is the
// previously-loaded token, if any (may be nil); its refresh token is
// preserved if the new token response doesn't include one.
func (a *app) authorize(ctx context.Context, client *http.Client, cfg *config.Config, acc *config.AccountConfig, account, authflow string, current *token.Token) (*token.Token, error) {
	provider, err := cfg.Provider(account)
	if err != nil {
		return nil, err
	}

	if acc.Authflow == "" {
		if authflow != "" {
			acc.Authflow = authflow
		} else {
			acc.Authflow = a.promptLine(fmt.Sprintf("Preferred OAuth2 flow (%q or %q or %q): ",
				config.AuthflowAuthCode, config.AuthflowLocalhostAuthCode, config.AuthflowDeviceCode))
		}
	}

	browserCfg := cfg.EffectiveBrowser(account)

	var tr oauth.TokenResponse
	switch acc.Authflow {
	case config.AuthflowAuthCode, config.AuthflowLocalhostAuthCode:
		tr, err = a.runAuthCodeFlow(ctx, client, provider, account, acc.Authflow, browserCfg)
	case config.AuthflowDeviceCode:
		tr, err = a.runDeviceCodeFlow(ctx, client, provider, browserCfg)
	default:
		return nil, fmt.Errorf("unknown OAuth2 flow %q; delete the stored token and start over", acc.Authflow)
	}
	if err != nil {
		return nil, err
	}

	tok := current
	if tok == nil {
		tok = &token.Token{}
	}
	if err := a.updateTokens(tok, tr, account); err != nil {
		return nil, err
	}
	return tok, nil
}

// runAuthCodeFlow runs the "authcode" (manual copy/paste) or
// "localhostauthcode" (local redirect listener) flow and exchanges the
// resulting code for tokens. If browserCfg is non-nil, it also tries to open
// authURL in the configured browser/profile.
func (a *app) runAuthCodeFlow(ctx context.Context, client *http.Client, provider config.ProviderConfig, account, mode string, browserCfg *config.BrowserConfig) (oauth.TokenResponse, error) {
	pkce, err := oauth.NewPKCE()
	if err != nil {
		return oauth.TokenResponse{}, err
	}

	redirectURI := provider.RedirectURI
	var ln net.Listener
	if mode == config.AuthflowLocalhostAuthCode {
		ln, err = oauth.ListenLocal(ctx)
		if err != nil {
			return oauth.TokenResponse{}, err
		}
		redirectURI = fmt.Sprintf("http://localhost:%d/", oauth.LocalPort(ln))
	}

	authURL, err := oauth.BuildAuthorizeURL(provider, account, redirectURI, pkce.Challenge)
	if err != nil {
		return oauth.TokenResponse{}, err
	}
	a.infoln(authURL)
	a.tryOpenBrowser(browserCfg, authURL)

	var code string
	if mode == config.AuthflowAuthCode {
		code = a.promptLine("Visit displayed URL to retrieve authorization code. Enter code from server (might be in browser address bar): ")
	} else {
		a.infof("Visit displayed URL to authorize this application. Waiting...")
		code, err = oauth.ServeOnce(ctx, ln)
		if err != nil {
			return oauth.TokenResponse{}, wrapAPIError(err)
		}
	}
	if code == "" {
		return oauth.TokenResponse{}, errors.New("did not obtain an authcode")
	}

	a.infoln("Exchanging the authorization code for an access token")
	tr, err := oauth.ExchangeAuthCode(ctx, client, provider, code, pkce.Verifier, redirectURI)
	if err != nil {
		return oauth.TokenResponse{}, wrapAPIError(err)
	}
	return tr, nil
}

// runDeviceCodeFlow runs the OAuth2 device-code flow, printing progress the
// same way the Python implementation does. If browserCfg is non-nil, it also
// tries to open the verification URL in the configured browser/profile.
func (a *app) runDeviceCodeFlow(ctx context.Context, client *http.Client, provider config.ProviderConfig, browserCfg *config.BrowserConfig) (oauth.TokenResponse, error) {
	dc, err := oauth.RequestDeviceCode(ctx, client, provider)
	if err != nil {
		return oauth.TokenResponse{}, wrapAPIError(err)
	}
	a.infoln(dc.Message)
	if dc.VerificationURI != "" {
		a.tryOpenBrowser(browserCfg, dc.VerificationURI)
	}
	a.infof("Polling...")

	tr, err := oauth.PollDeviceToken(ctx, client, provider, dc, time.Sleep, func() { a.infof(".") })
	if err != nil {
		switch {
		case errors.Is(err, oauth.ErrAuthorizationDeclined):
			a.infoln(" user declined authorization.")
			return oauth.TokenResponse{}, errors.New("authorization declined")
		case errors.Is(err, oauth.ErrDeviceCodeExpired):
			a.infoln(" too much time has elapsed.")
			return oauth.TokenResponse{}, errors.New("too much time elapsed for device code")
		default:
			return oauth.TokenResponse{}, wrapAPIError(err)
		}
	}
	a.infoln()
	return tr, nil
}
