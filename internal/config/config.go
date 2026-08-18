// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

// Package config loads and validates the omt config.yaml file, including the
// XDG base-directory lookup used to locate it.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ProviderConfig holds the OAuth2 endpoints and credentials for one mail
// provider (e.g. the "google" or "o365" entries under the "global" section).
type ProviderConfig struct {
	AuthorizeEndpoint  string `yaml:"authorize_endpoint"`
	DevicecodeEndpoint string `yaml:"devicecode_endpoint"`
	TokenEndpoint      string `yaml:"token_endpoint"`
	RedirectURI        string `yaml:"redirect_uri"`
	Tenant             string `yaml:"tenant"`
	IMAPEndpoint       string `yaml:"imap_endpoint"`
	POPEndpoint        string `yaml:"pop_endpoint"`
	SMTPEndpoint       string `yaml:"smtp_endpoint"`
	SASLMethod         string `yaml:"sasl_method"`
	Scope              string `yaml:"scope"`
	ClientID           string `yaml:"client_id"`
	ClientSecret       string `yaml:"client_secret"`
}

// Authflow values accepted in AccountConfig.Authflow (and by the
// --authflow flag): the OAuth2 grant used to obtain the first token pair.
const (
	// AuthflowAuthCode is the authorization-code flow, with the code
	// copy/pasted back into the terminal by the user.
	AuthflowAuthCode = "authcode"
	// AuthflowLocalhostAuthCode is the authorization-code flow, with a
	// short-lived loopback listener catching the redirect automatically.
	AuthflowLocalhostAuthCode = "localhostauthcode"
	// AuthflowDeviceCode is the device-code flow (RFC 8628).
	AuthflowDeviceCode = "devicecode"
)

// AccountConfig holds the per-account settings referencing a provider.
type AccountConfig struct {
	Provider string         `yaml:"provider"`
	Authflow string         `yaml:"authflow"`
	Browser  *BrowserConfig `yaml:"browser"`
}

// GlobalSection holds the storage settings plus an arbitrary set of named
// providers (commonly "google" and "o365").
type GlobalSection struct {
	Storage        string         `yaml:"storage"`
	KeyringBackend string         `yaml:"keyring-backend"`
	Browser        *BrowserConfig `yaml:"browser"`
	// Debug, when true, makes "omt daemon" print each check it performs
	// (which account, what it found, what it decided) in addition to the
	// refreshes/errors it always prints. Equivalent to always passing
	// -d/--debug to "omt daemon"; unlike that flag it doesn't affect other
	// commands (which use -d/--debug for raw HTTP response logging).
	Debug     bool                      `yaml:"debug"`
	Daemon    *DaemonConfig             `yaml:"daemon"`
	Providers map[string]ProviderConfig `yaml:",inline"`
}

// DaemonConfig configures the "omt daemon" subcommand.
type DaemonConfig struct {
	// Interval is how often the daemon checks every account's stored token,
	// as a Go duration string (e.g. "5m", "90s"). Defaults to 5m if unset.
	Interval string `yaml:"interval"`
}

// BrowserConfig configures which browser (and, for browsers that support it,
// which profile) is launched to visit an interactive OAuth2 authorization
// URL, instead of relying on the OS default browser/profile.
//
// Example (macOS, opening a specific Firefox-based browser with a named
// profile via `open`):
//
//	browser:
//	  command: open
//	  args: ["-a", "Zen Browser", "--args", "-P", "my-profile"]
//
// The target URL is always appended as the final argument, so the command
// above ultimately runs:
//
//	open -a "Zen Browser" --args -P my-profile "https://accounts.google.com/..."
type BrowserConfig struct {
	// Command is the executable to run (e.g. "open" on macOS, "xdg-open" on
	// Linux, or a browser binary directly).
	Command string `yaml:"command"`
	// Args are extra arguments placed before the URL, e.g. to select an
	// application and/or profile.
	Args []string `yaml:"args"`
	// Disabled, when true, suppresses auto-opening a browser (the
	// authorization URL is still printed for the user to open manually).
	// Setting this at the account level overrides a global default.
	Disabled bool `yaml:"disabled"`
}

// Config mirrors the structure of config.yaml.
type Config struct {
	Global   *GlobalSection           `yaml:"global"`
	Accounts map[string]AccountConfig `yaml:"accounts"`
}

// Provider returns the ProviderConfig referenced by the given account's
// "provider" field, or an error if the account or its provider is unknown.
func (c *Config) Provider(account string) (ProviderConfig, error) {
	acc, ok := c.Accounts[account]
	if !ok {
		return ProviderConfig{}, fmt.Errorf("account %q not found in config", account)
	}
	if c.Global == nil {
		return ProviderConfig{}, errors.New("global section does not exist in config")
	}
	p, ok := c.Global.Providers[acc.Provider]
	if !ok {
		return ProviderConfig{}, fmt.Errorf("provider %q (referenced by account %q) not found in global config", acc.Provider, account)
	}
	return p, nil
}

// EffectiveBrowser returns the browser launch configuration that applies to
// account: the account's own "browser" section if set, otherwise the global
// default, otherwise nil (meaning: don't auto-open a browser, just print the
// URL). An explicit "disabled: true" always wins over a global default, even
// if the account itself defines no other browser settings.
func (c *Config) EffectiveBrowser(account string) *BrowserConfig {
	if acc, ok := c.Accounts[account]; ok && acc.Browser != nil {
		if acc.Browser.Disabled {
			return nil
		}
		return acc.Browser
	}
	if c.Global != nil && c.Global.Browser != nil {
		if c.Global.Browser.Disabled {
			return nil
		}
		return c.Global.Browser
	}
	return nil
}

// xdgConfigDirs returns the XDG config directory search path, most-preferred
// first: $XDG_CONFIG_HOME (default "$HOME/.config"), followed by the
// colon-separated entries of $XDG_CONFIG_DIRS (default "/etc/xdg").
func xdgConfigDirs() []string {
	var dirs []string

	home := os.Getenv("XDG_CONFIG_HOME")
	if home == "" {
		if h, err := os.UserHomeDir(); err == nil {
			home = filepath.Join(h, ".config")
		}
	}
	if home != "" {
		dirs = append(dirs, home)
	}

	extra := os.Getenv("XDG_CONFIG_DIRS")
	if extra == "" {
		extra = "/etc/xdg"
	}
	for d := range strings.SplitSeq(extra, string(os.PathListSeparator)) {
		if d != "" {
			dirs = append(dirs, d)
		}
	}

	return dirs
}

// LocateConfigFile searches the XDG config directories (in priority order)
// for a directory named appName, mirroring pyxdg's load_first_config(appName)
// as used by the original Python implementation, and returns the path to
// "<dir>/<appName>/config.yaml".
func LocateConfigFile(appName string) (string, error) {
	for _, dir := range xdgConfigDirs() {
		candidate := filepath.Join(dir, appName)
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return filepath.Join(candidate, "config.yaml"), nil
		}
	}
	return "", fmt.Errorf("no %q configuration directory found in XDG config dirs", appName)
}

// Load reads and parses the YAML config file at path.
func Load(path string) (*Config, error) {
	// #nosec G304 -- path is this program's own config file, located by
	// LocateConfigFile under the user's XDG config directories. Reading a
	// caller-supplied config path is the entire point of the function.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &cfg, nil
}
