// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

package browser

import (
	"os/exec"
	"testing"

	"github.com/schretzi/oauthmailtoken/internal/config"
)

func TestOpenNilConfigIsNoop(t *testing.T) {
	if err := Open(nil, "https://example.com"); err != nil {
		t.Errorf("Open(nil, ...) = %v, want nil", err)
	}
}

func TestOpenEmptyCommandIsNoop(t *testing.T) {
	if err := Open(&config.BrowserConfig{}, "https://example.com"); err != nil {
		t.Errorf("Open(empty command, ...) = %v, want nil", err)
	}
}

func TestOpenLaunchesCommandWithURLAppended(t *testing.T) {
	truePath, err := exec.LookPath("true")
	if err != nil {
		t.Skip(`"true" not found on PATH, skipping`)
	}

	cfg := &config.BrowserConfig{
		Command: truePath,
		Args:    []string{"-a", "SomeApp"},
	}
	if err := Open(cfg, "https://example.com/auth?code=1"); err != nil {
		t.Errorf("Open returned error: %v", err)
	}
}

func TestOpenUnknownCommandReturnsError(t *testing.T) {
	cfg := &config.BrowserConfig{Command: "definitely-not-a-real-command-omt-test"}
	if err := Open(cfg, "https://example.com"); err == nil {
		t.Error("expected error for a nonexistent command")
	}
}
