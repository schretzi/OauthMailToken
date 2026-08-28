// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

package cli

import (
	"github.com/spf13/cobra"

	"github.com/schretzi/oauthmailtoken/internal/version"
)

// licenseNotice is the "Appropriate Legal Notices" text required by the GNU
// GPL: a copyright notice, the absence of warranty, that the work may be
// conveyed under the GPL, and where to read the licence. `omt version` is
// the convenient, prominently visible place for it in a CLI.
const licenseNotice = `Copyright (C) 2026 schretzi
Derived from mutt_oauth2.py, Copyright (C) 2020 Alexander Perlis.
License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.`

// newVersionCmd builds the "version" subcommand from the shared
// internal/version package, so omt, kerberoskeepalive and macswitcher all
// report build information in the same shape.
//
// The build variables now live in internal/version, so .goreleaser.yaml's
// ldflags point there rather than at this package.
func newVersionCmd(_ *app) *cobra.Command {
	cmd := version.NewCommand(appName, licenseNotice)
	// Usage errors must exit 2, which means the shared validator has to be
	// wrapped in omt's own classifier.
	cmd.Args = usageArgs(cobra.NoArgs)
	return cmd
}
