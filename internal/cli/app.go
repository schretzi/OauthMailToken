// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

package cli

import (
	"bufio"
	"errors"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/schretzi/oauthmailtoken/internal/browser"
	"github.com/schretzi/oauthmailtoken/internal/config"
	"github.com/schretzi/oauthmailtoken/internal/oauth"
	"github.com/schretzi/oauthmailtoken/internal/token"
)

// accountNames returns the configured account names in sorted order, so
// every command that iterates over accounts produces stable output.
func accountNames(cfg *config.Config) []string {
	return slices.Sorted(maps.Keys(cfg.Accounts))
}

// httpClient builds the HTTP client used for all token endpoint/device code
// requests, wiring up response-body debug logging when -d/--debug is set.
func (a *app) httpClient() *http.Client {
	client := &http.Client{Timeout: httpTimeout}
	if a.debug {
		client.Transport = debugTransport{rt: http.DefaultTransport, out: a.err}
	}
	return client
}

// printAccessToken writes tok's access token to the result stream. In
// verbose mode it is preceded by an "Access Token: " label - on the
// diagnostic stream, so the result stream stays exactly the token.
func (a *app) printAccessToken(tok *token.Token) {
	if a.verbose {
		a.infof("Access Token: ")
	}
	a.outln(tok.AccessToken)
}

// loadTokenWithDefaultsNotice loads the stored token for account, printing
// the same informational notices as the Python implementation's readToken()
// when the config doesn't specify a storage backend.
func (a *app) loadTokenWithDefaultsNotice(cfg *config.Config, account string) (*token.Token, error) {
	if cfg.Global.Storage == "" {
		a.infoln("Storage not set, trying keyring with system backend")
		cfg.Global.Storage = storageKeyring
		cfg.Global.KeyringBackend = keyringBackendSystem
	}
	if cfg.Global.Storage == storageKeyring && cfg.Global.KeyringBackend == "" {
		a.infoln("Keyring Backend not set, trying keyring with system backend")
		cfg.Global.KeyringBackend = keyringBackendSystem
	}
	return token.Load(account)
}

// tryOpenBrowser attempts to open targetURL via cfg's configured browser
// command (see internal/browser). It never fails the calling flow: cfg may
// be nil (no browser configured - a no-op), and any launch error is only
// printed as a notice, since the URL was already printed for the user to
// open manually.
func (a *app) tryOpenBrowser(cfg *config.BrowserConfig, targetURL string) {
	if err := browser.Open(cfg, targetURL); err != nil {
		a.infof("NOTICE: could not launch configured browser (%v); open the URL above manually.\n", err)
	}
}

// promptLine writes prompt to the diagnostic stream and reads one line of
// the answer from the input stream.
func (a *app) promptLine(prompt string) string {
	a.infof("%s", prompt)
	line, _ := bufio.NewReader(a.in).ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

// oneLine collapses a (possibly multi-line) error message into one line so
// it doesn't break tabwriter's column alignment.
func oneLine(err error) string {
	return strings.ReplaceAll(err.Error(), "\n", "; ")
}

// wrapAPIError turns an *oauth.APIError into a plain error whose message
// matches the two lines the Python implementation prints (error code, then
// description), so a single Println at the top level reproduces it.
func wrapAPIError(err error) error {
	var apiErr *oauth.APIError
	if errors.As(err, &apiErr) {
		msg := apiErr.Code
		if apiErr.Description != "" {
			msg += "\n" + apiErr.Description
		}
		return errors.New(msg)
	}
	return err
}
