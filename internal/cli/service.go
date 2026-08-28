// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/schretzi/oauthmailtoken/internal/service"
)

// launchAgentService describes omt's own launchd job: the foreground process
// it runs is `omt daemon`.
//
// "service" means this job. `daemon` is the process that job runs - the two
// are deliberately never the same word.
func launchAgentService() *service.Service {
	return service.New(appName, "daemon")
}

// newServiceCmd builds the `service` subtree from the shared implementation,
// so omt, kerberoskeepalive and macswitcher expose an identical surface.
//
// Until now omt had no install command at all: its LaunchAgent was a
// hand-maintained plist in the MacbookSetup repo, which is why it drifted
// (an org.* label, a bash -lc redirect for logging, and no rotation).
// The *app parameter is unused - the shared command writes through cobra's
// own streams, which newRootCmd already points at the app's - but every
// newXCmd here takes one, and breaking that pattern for a single command is
// worse than an ignored argument.
func newServiceCmd(_ *app) *cobra.Command {
	return service.NewCommand(launchAgentService(), func(*service.Service) error {
		// Installing an agent whose config does not parse just produces a
		// job that crash-loops in the background.
		if _, err := loadConfigWithProviders(); err != nil {
			return fmt.Errorf("config invalid: %w", err)
		}
		return nil
	})
}
