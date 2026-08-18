// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

package cli

import (
	"context"
	"fmt"
)

// runGet implements the root command: print a valid access token,
// transparently authorizing (if no token exists yet) or refreshing (if the
// access token expired) as needed. This is what mutt calls.
//
// forceAuthorize is the -a/--authorize flag, kept for backwards
// compatibility with the original Python CLI; "omt authorize <account>" is
// the same thing spelled as a subcommand.
func runGet(ctx context.Context, a *app, account string, forceAuthorize bool, authflow string) error {
	cfg, acc, err := loadConfigAndAccount(account)
	if err != nil {
		return err
	}

	tok, err := a.loadTokenWithDefaultsNotice(cfg, account)
	if err != nil {
		return fmt.Errorf("reading stored token: %w", err)
	}

	client := a.httpClient()

	if tok == nil {
		a.infoln("Token not found, please authorize")
		tok, err = a.authorize(ctx, client, cfg, &acc, account, authflow, tok)
		if err != nil {
			return err
		}
	}

	if forceAuthorize {
		a.infoln("Authorization chosen")
		tok, err = a.authorize(ctx, client, cfg, &acc, account, authflow, tok)
		if err != nil {
			return err
		}
	}

	if !tok.IsValid() {
		if a.verbose {
			a.infoln("NOTICE: Invalid or expired access token; using refresh token to obtain new access token.")
		}
		if err := a.refreshAccessToken(ctx, client, cfg, account, tok); err != nil {
			return err
		}
	}

	a.printAccessToken(tok)
	return nil
}
