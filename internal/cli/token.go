// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/schretzi/oauthmailtoken/internal/token"
)

// newTokenCmd builds the "token" subcommand: print *only* the currently
// stored access token, straight from the keyring, with nothing else on
// stdout - so it can be safely embedded in a command substitution and
// passed to another program. Unlike the root command it never authorizes or
// refreshes: it is a read-only lookup of whatever is currently stored, and
// fails if there is nothing there.
func newTokenCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "token <account>",
		Short: "Print the stored access token for one account, and nothing else",
		Long: `Print the access token currently stored for the account, straight from the
keyring. Nothing else is written to stdout, so this is safe to embed in a
command substitution.

Unlike the root command, "token" never authorizes and never refreshes: it
reports exactly what is stored, and fails if the account was never
authorized. If the stored token has expired it is still printed, with a
warning on stderr.`,
		Example: `  curl -H "Authorization: Bearer $(omt token me@gmail.com)" https://example.com`,

		Args:              usageArgs(cobra.ExactArgs(1)),
		ValidArgsFunction: completeAccounts,

		RunE: func(_ *cobra.Command, args []string) error {
			return a.runToken(args[0])
		},
	}
}

func (a *app) runToken(account string) error {
	if _, _, err := loadConfigAndAccount(account); err != nil {
		return err
	}

	// Deliberately not loadTokenWithDefaultsNotice: its notices would be
	// noise for a command whose whole promise is "just the token".
	tok, err := token.Load(account)
	if err != nil {
		return fmt.Errorf("reading stored token: %w", err)
	}
	if tok == nil || tok.AccessToken == "" {
		return fmt.Errorf("no stored token for %q; run %q first", account, "omt authorize "+account)
	}
	if !tok.IsValid() {
		a.infof("WARNING: stored token for %q is expired; run \"omt refresh %s\" (or \"omt authorize %s\" if that fails).\n", account, account, account)
	}

	a.outln(tok.AccessToken)
	return nil
}
