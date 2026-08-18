// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

package cli

import (
	"strings"

	"github.com/spf13/cobra"
)

// completeAccounts is the ValidArgsFunction for every command that takes an
// account argument. It reads the configured account names straight out of
// config.yaml, so completion always reflects the current config without
// needing to be regenerated - and, unlike the previous hand-written
// completion scripts, without shelling out to "omt list-accounts" on every
// TAB press.
//
// Completion must never fail loudly: if the config is missing or malformed,
// the right behaviour is to offer nothing, not to spray an error into the
// user's prompt.
func completeAccounts(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		// The account argument has already been given.
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	cfg, err := loadConfig()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	var names []string
	for _, name := range accountNames(cfg) {
		if strings.HasPrefix(name, toComplete) {
			names = append(names, name)
		}
	}
	return names, cobra.ShellCompDirectiveNoFileComp
}
