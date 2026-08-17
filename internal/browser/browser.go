// Package browser launches a user-configured web browser (optionally with a
// specific application/profile) to visit an OAuth2 authorization URL,
// instead of relying on whatever the OS considers the default browser.
package browser

import (
	"os/exec"

	"github.com/schretzi/oauthmailtoken/internal/config"
)

// Open launches cfg's configured command with its args plus targetURL
// appended as the final argument, without waiting for the process to exit
// (so it doesn't block while the browser/app stays open).
//
// If cfg is nil or has an empty Command, Open does nothing and returns nil -
// callers should still print targetURL so the user has something to click
// or copy/paste manually.
func Open(cfg *config.BrowserConfig, targetURL string) error {
	if cfg == nil || cfg.Command == "" {
		return nil
	}
	args := make([]string, 0, len(cfg.Args)+1)
	args = append(args, cfg.Args...)
	args = append(args, targetURL)
	return exec.Command(cfg.Command, args...).Start()
}
