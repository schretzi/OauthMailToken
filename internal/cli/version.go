// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

package cli

import (
	"runtime"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// Build information, injected at link time by goreleaser (see
// .goreleaser.yaml's ldflags). The defaults are what a plain `go build`
// produces; buildInfo() fills in what it can from the embedded module data
// in that case.
var (
	version = "dev"
	commit  = ""
	date    = ""
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

// newVersionCmd builds the "version" subcommand.
func newVersionCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the omt version, build info and licence",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(*cobra.Command, []string) error {
			v, c, d := buildInfo()
			a.outf("omt %s\n", v)
			if c != "" {
				a.outf("  commit:  %s\n", c)
			}
			if d != "" {
				a.outf("  built:   %s\n", d)
			}
			a.outf("  go:      %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
			a.outf("\n%s\n", licenseNotice)
			return nil
		},
	}
}

// buildInfo returns the version, commit and build date, preferring the
// link-time values and falling back to the VCS stamps the Go toolchain
// embeds when building from a source checkout.
func buildInfo() (v, c, d string) {
	v, c, d = version, commit, date

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return v, c, d
	}
	if v == "dev" && info.Main.Version != "" && info.Main.Version != "(devel)" {
		v = info.Main.Version
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if c == "" {
				c = s.Value
			}
		case "vcs.time":
			if d == "" {
				d = s.Value
			}
		}
	}
	return v, c, d
}
