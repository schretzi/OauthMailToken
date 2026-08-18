// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/schretzi/oauthmailtoken/internal/config"
)

const testConfigYAML = `
global:
  storage: keyring
  keyring-backend: system
  google:
    authorize_endpoint: https://accounts.google.com/o/oauth2/auth
    devicecode_endpoint: https://oauth2.googleapis.com/device/code
    token_endpoint: https://accounts.google.com/o/oauth2/token
    redirect_uri: urn:ietf:wg:oauth:2.0:oob
    scope: https://mail.google.com/
    client_id: cid
    client_secret: csecret
    sasl_method: OAUTHBEARER
accounts:
  me@gmail.com:
    provider: google
    authflow: localhostauthcode
`

// withXDGConfig writes an omt config.yaml under a fresh XDG_CONFIG_HOME and
// points the environment at it for the duration of the test.
func withXDGConfig(t *testing.T, yamlContent string) {
	t.Helper()

	home := t.TempDir()
	omtDir := filepath.Join(home, appName)
	if err := os.MkdirAll(omtDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(omtDir, "config.yaml"), []byte(yamlContent), 0o600); err != nil {
		t.Fatal(err)
	}

	// t.Setenv restores the previous value (or unsets it) at test end.
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("XDG_CONFIG_DIRS", t.TempDir())
}

// execute runs the real command tree with argv and returns what it wrote to
// each stream. Driving the actual cobra tree - rather than calling the
// command implementations directly - means these tests also cover flag
// parsing, argument validation and dispatch, which is where a CLI usually
// breaks.
func execute(t *testing.T, argv ...string) (stdout, stderr string, err error) {
	t.Helper()

	if argv == nil {
		// A nil slice makes cobra fall back to os.Args[1:], which would run
		// the test binary's own flags through the command tree.
		argv = []string{}
	}

	var out, errOut bytes.Buffer
	err = Execute(t.Context(), argv, &out, &errOut, strings.NewReader(""))
	return out.String(), errOut.String(), err
}

// newTestApp returns an app writing to buffers, for the internals that are
// exercised below the command layer (the daemon tick, mostly).
func newTestApp(debug bool) (a *app, stdout, stderr *bytes.Buffer) {
	stdout, stderr = &bytes.Buffer{}, &bytes.Buffer{}
	return &app{out: stdout, err: stderr, in: strings.NewReader(""), debug: debug}, stdout, stderr
}

// loadTestConfig loads the config.yaml that withXDGConfig just wrote.
func loadTestConfig(t *testing.T) *config.Config {
	t.Helper()

	cfgPath, err := config.LocateConfigFile(appName)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// writeJSON encodes v as the JSON body of a stub OAuth2 endpoint response.
// It exists so the encode error is actually checked: a silent failure here
// would surface as a confusing "decoding response" error from the code under
// test rather than as a broken stub.
//
// It runs inside an httptest handler goroutine, so it reports with t.Errorf
// rather than t.Fatalf - the latter may only be called from the goroutine
// running the test.
func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("encoding stub response: %v", err)
	}
}

func trimTrailingNewline(s string) string {
	return strings.TrimRight(s, "\r\n")
}

// lines splits trimmed output into its non-empty lines.
func lines(s string) []string {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}
