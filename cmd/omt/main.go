// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

// Command omt obtains and prints a valid OAuth2 access token for use by mutt
// (or any other tool that wants an OAuth2 bearer token for IMAP, POP or
// SMTP). It is a Go port of the original Python "Mutt OAuth2 token
// management" script, storing state in the OS keyring instead of an
// encrypted token file.
//
// This package is deliberately a thin wrapper: everything the tool actually
// does lives in internal/cli, so it can be exercised by tests without
// spawning a process.
package main

import (
	"os"

	"github.com/schretzi/oauthmailtoken/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
