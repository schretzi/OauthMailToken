package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/schretzi/oauthmailtoken/internal/config"
	"github.com/schretzi/oauthmailtoken/internal/token"
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
	omtDir := filepath.Join(home, "omt")
	if err := os.MkdirAll(omtDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(omtDir, "config.yaml"), []byte(yamlContent), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, kv := range [][2]string{
		{"XDG_CONFIG_HOME", home},
		{"XDG_CONFIG_DIRS", t.TempDir()},
	} {
		old, had := os.LookupEnv(kv[0])
		os.Setenv(kv[0], kv[1])
		t.Cleanup(func() {
			if had {
				os.Setenv(kv[0], old)
			} else {
				os.Unsetenv(kv[0])
			}
		})
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()

	fn()

	w.Close()
	out, _ := io.ReadAll(r)
	return string(out)
}

func TestRunPrintsValidStoredAccessToken(t *testing.T) {
	withXDGConfig(t, testConfigYAML)
	keyring.MockInit()

	want := &token.Token{
		AccessToken:           "already-valid-access-token",
		AccessTokenExpiration: time.Now().Add(time.Hour).Format(time.RFC3339),
		RefreshToken:          "refresh-abc",
	}
	if err := token.Store("me@gmail.com", want); err != nil {
		t.Fatal(err)
	}

	args := &Args{Account: "me@gmail.com"}
	var runErr error
	out := captureStdout(t, func() {
		runErr = run(args)
	})
	if runErr != nil {
		t.Fatalf("run returned error: %v", runErr)
	}
	if got := trimTrailingNewline(out); got != want.AccessToken {
		t.Errorf("stdout = %q, want %q", out, want.AccessToken)
	}
}

func TestRunUnknownAccount(t *testing.T) {
	withXDGConfig(t, testConfigYAML)
	keyring.MockInit()

	args := &Args{Account: "nobody@gmail.com"}
	if err := run(args); err == nil {
		t.Fatal("expected error for unknown account")
	}
}

func TestRunListAccountsCommand(t *testing.T) {
	withXDGConfig(t, `
accounts:
  b@gmail.com:
    provider: google
  a@outlook.com:
    provider: o365
`)

	out := captureStdout(t, func() {
		if err := run(&Args{Command: CmdListAccounts}); err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	want := []string{"a@outlook.com", "b@gmail.com"}
	if len(lines) != len(want) {
		t.Fatalf("got %v lines, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestRunListAccountsCommandNoAccountsSection(t *testing.T) {
	withXDGConfig(t, "global:\n  storage: keyring\n")
	if err := run(&Args{Command: CmdListAccounts}); err == nil {
		t.Fatal("expected error when accounts section is missing")
	}
}

func TestRunTokenCommandPrintsOnlyTheStoredToken(t *testing.T) {
	withXDGConfig(t, testConfigYAML)
	keyring.MockInit()

	want := &token.Token{
		AccessToken:           "the-stored-access-token",
		AccessTokenExpiration: time.Now().Add(time.Hour).Format(time.RFC3339),
		RefreshToken:          "refresh-abc",
	}
	if err := token.Store("me@gmail.com", want); err != nil {
		t.Fatal(err)
	}

	args := &Args{Command: CmdToken, Account: "me@gmail.com"}
	var runErr error
	out := captureStdout(t, func() {
		runErr = run(args)
	})
	if runErr != nil {
		t.Fatalf("run returned error: %v", runErr)
	}
	if got := trimTrailingNewline(out); got != want.AccessToken {
		t.Errorf("stdout = %q, want exactly %q (and nothing else)", out, want.AccessToken)
	}
}

func TestRunTokenCommandNoStoredToken(t *testing.T) {
	withXDGConfig(t, testConfigYAML)
	keyring.MockInit()

	if err := run(&Args{Command: CmdToken, Account: "me@gmail.com"}); err == nil {
		t.Fatal("expected error when no token is stored yet")
	}
}

func TestRunTokenCommandUnknownAccount(t *testing.T) {
	withXDGConfig(t, testConfigYAML)
	keyring.MockInit()

	if err := run(&Args{Command: CmdToken, Account: "nobody@gmail.com"}); err == nil {
		t.Fatal("expected error for unknown account")
	}
}

func TestRunTokenCommandExpiredTokenStillPrintedWithWarning(t *testing.T) {
	withXDGConfig(t, testConfigYAML)
	keyring.MockInit()

	expired := &token.Token{
		AccessToken:           "expired-but-still-stored",
		AccessTokenExpiration: time.Now().Add(-time.Hour).Format(time.RFC3339),
		RefreshToken:          "refresh-abc",
	}
	if err := token.Store("me@gmail.com", expired); err != nil {
		t.Fatal(err)
	}

	args := &Args{Command: CmdToken, Account: "me@gmail.com"}
	var runErr error
	out := captureStdout(t, func() {
		runErr = run(args)
	})
	if runErr != nil {
		t.Fatalf("run returned error: %v", runErr)
	}
	// The warning about expiry must go to stderr, not stdout - stdout must
	// stay exactly the token so it's safe to embed in a command
	// substitution.
	if got := trimTrailingNewline(out); got != expired.AccessToken {
		t.Errorf("stdout = %q, want exactly %q", out, expired.AccessToken)
	}
}

func TestRunCompletionCommandBash(t *testing.T) {
	out := captureStdout(t, func() {
		if err := run(&Args{Command: CmdCompletion, Shell: "bash"}); err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	})
	if !strings.Contains(out, "complete -F _omt_completion omt") {
		t.Errorf("bash completion script missing expected registration line, got: %s", out)
	}
}

func TestRunCompletionCommandZsh(t *testing.T) {
	out := captureStdout(t, func() {
		if err := run(&Args{Command: CmdCompletion, Shell: "zsh"}); err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	})
	if !strings.Contains(out, "compdef _omt omt") {
		t.Errorf("zsh completion script missing expected registration line, got: %s", out)
	}
}

func TestRunRefreshCommandForcesRefreshEvenIfStillValid(t *testing.T) {
	var gotGrantType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		gotGrantType = r.PostForm.Get("grant_type")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":             "brand-new-access-token",
			"refresh_token":            "brand-new-refresh-token",
			"expires_in":               3600,
			"refresh_token_expires_in": 7776000, // 90 days - some providers (not Google/MS) do send this
		})
	}))
	defer srv.Close()

	withXDGConfig(t, `
global:
  storage: keyring
  google:
    token_endpoint: `+srv.URL+`
    scope: https://mail.google.com/
    client_id: cid
    client_secret: csecret
    sasl_method: OAUTHBEARER
accounts:
  me@gmail.com:
    provider: google
`)
	keyring.MockInit()

	// Store a token that is still comfortably valid.
	if err := token.Store("me@gmail.com", &token.Token{
		AccessToken:           "still-valid-access-token",
		AccessTokenExpiration: time.Now().Add(time.Hour).Format(time.RFC3339),
		RefreshToken:          "old-refresh-token",
	}); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if err := run(&Args{Command: CmdRefresh, Account: "me@gmail.com"}); err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	})

	if gotGrantType != "refresh_token" {
		t.Errorf("grant_type = %q, want refresh_token", gotGrantType)
	}
	if got := trimTrailingNewline(out); got != "brand-new-access-token" {
		t.Errorf("stdout = %q, want %q", out, "brand-new-access-token")
	}

	stored, err := token.Load("me@gmail.com")
	if err != nil {
		t.Fatal(err)
	}
	if stored.AccessToken != "brand-new-access-token" {
		t.Errorf("stored access token = %q, want the refreshed one", stored.AccessToken)
	}
	if stored.RefreshTokenExpiration == "" {
		t.Error("expected RefreshTokenExpiration to be set from the response's refresh_token_expires_in")
	} else if exp, err := token.ParseTime(stored.RefreshTokenExpiration); err != nil {
		t.Errorf("stored RefreshTokenExpiration did not parse: %v", err)
	} else if d := time.Until(exp); d < 89*24*time.Hour || d > 91*24*time.Hour {
		t.Errorf("RefreshTokenExpiration %v not ~90d from now", exp)
	}
}

func TestRunRefreshCommandNoStoredToken(t *testing.T) {
	withXDGConfig(t, testConfigYAML)
	keyring.MockInit()

	err := run(&Args{Command: CmdRefresh, Account: "me@gmail.com"})
	if err == nil {
		t.Fatal("expected error when no token is stored yet")
	}
}

func TestRunRefreshCommandAllAccounts(t *testing.T) {
	var refreshedAccounts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		refreshedAccounts = append(refreshedAccounts, r.PostForm.Get("refresh_token"))
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "new-for-" + r.PostForm.Get("refresh_token"),
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	withXDGConfig(t, `
global:
  storage: keyring
  google:
    token_endpoint: `+srv.URL+`
    scope: https://mail.google.com/
    client_id: cid
    client_secret: csecret
    sasl_method: OAUTHBEARER
accounts:
  has-refresh@gmail.com:
    provider: google
  not-authorized@gmail.com:
    provider: google
  no-refresh-token@gmail.com:
    provider: google
`)
	keyring.MockInit()

	if err := token.Store("has-refresh@gmail.com", &token.Token{
		AccessToken:           "old-access",
		AccessTokenExpiration: time.Now().Add(time.Hour).Format(time.RFC3339),
		RefreshToken:          "refresh-for-has-refresh",
	}); err != nil {
		t.Fatal(err)
	}
	if err := token.Store("no-refresh-token@gmail.com", &token.Token{
		AccessToken:           "old-access",
		AccessTokenExpiration: time.Now().Add(time.Hour).Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	// not-authorized@gmail.com has no stored token at all.

	out := captureStdout(t, func() {
		if err := run(&Args{Command: CmdRefresh}); err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	})

	if len(refreshedAccounts) != 1 || refreshedAccounts[0] != "refresh-for-has-refresh" {
		t.Errorf("expected exactly one refresh call for has-refresh@gmail.com's refresh token, got %v", refreshedAccounts)
	}

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 { // header + 3 accounts
		t.Fatalf("expected header + 3 rows, got %d lines:\n%s", len(lines), out)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "has-refresh@gmail.com") || !strings.Contains(joined, "refreshed") {
		t.Errorf("expected a refreshed row for has-refresh@gmail.com, got:\n%s", out)
	}
	if !strings.Contains(joined, "not-authorized@gmail.com") || !strings.Contains(joined, "skipped: not authorized") {
		t.Errorf("expected a skipped row for not-authorized@gmail.com, got:\n%s", out)
	}
	if !strings.Contains(joined, "no-refresh-token@gmail.com") || !strings.Contains(joined, "skipped: no refresh token") {
		t.Errorf("expected a skipped row for no-refresh-token@gmail.com, got:\n%s", out)
	}

	stored, err := token.Load("has-refresh@gmail.com")
	if err != nil {
		t.Fatal(err)
	}
	if stored.AccessToken != "new-for-refresh-for-has-refresh" {
		t.Errorf("stored access token = %q, want the refreshed one", stored.AccessToken)
	}
}

func TestRunRefreshCommandAllAccountsReportsFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"error":             "invalid_grant",
			"error_description": "Token has been expired or revoked.",
		})
	}))
	defer srv.Close()

	withXDGConfig(t, `
global:
  storage: keyring
  google:
    token_endpoint: `+srv.URL+`
    scope: https://mail.google.com/
    client_id: cid
    client_secret: csecret
    sasl_method: OAUTHBEARER
accounts:
  broken@gmail.com:
    provider: google
`)
	keyring.MockInit()

	if err := token.Store("broken@gmail.com", &token.Token{
		AccessToken:           "old-access",
		AccessTokenExpiration: time.Now().Add(time.Hour).Format(time.RFC3339),
		RefreshToken:          "refresh-for-broken",
	}); err != nil {
		t.Fatal(err)
	}

	var runErr error
	out := captureStdout(t, func() {
		runErr = run(&Args{Command: CmdRefresh})
	})
	if runErr == nil {
		t.Fatal("expected run to return an error when a refresh attempt fails")
	}
	if !strings.Contains(out, "broken@gmail.com") || !strings.Contains(out, "error:") {
		t.Errorf("expected an error row for broken@gmail.com, got:\n%s", out)
	}
}

func TestFormatAccountStatus(t *testing.T) {
	fixedErr := errors.New("keyring unavailable")

	cases := []struct {
		name                  string
		tok                   *token.Token
		loadErr               error
		wantStatus            string
		wantExpiresSub        string // substring expected in the expires column
		wantRefresh           string
		wantRefreshExpiresSub string // substring expected in the refresh-expires column
	}{
		{
			name:                  "load error",
			loadErr:               fixedErr,
			wantStatus:            "error",
			wantExpiresSub:        "keyring unavailable",
			wantRefresh:           "-",
			wantRefreshExpiresSub: "-",
		},
		{
			name:                  "never authorized",
			tok:                   nil,
			wantStatus:            "not authorized",
			wantRefresh:           "-",
			wantRefreshExpiresSub: "-",
		},
		{
			name:                  "valid, has refresh token, provider didn't report its expiry",
			tok:                   &token.Token{AccessToken: "a", AccessTokenExpiration: time.Now().Add(30 * time.Minute).Format(time.RFC3339), RefreshToken: "r"},
			wantStatus:            "valid",
			wantExpiresSub:        "(in ",
			wantRefresh:           "yes",
			wantRefreshExpiresSub: "unknown",
		},
		{
			name: "valid, refresh token has a known future expiry",
			tok: &token.Token{
				AccessToken:            "a",
				AccessTokenExpiration:  time.Now().Add(30 * time.Minute).Format(time.RFC3339),
				RefreshToken:           "r",
				RefreshTokenExpiration: time.Now().Add(90 * 24 * time.Hour).Format(time.RFC3339),
			},
			wantStatus:            "valid",
			wantRefresh:           "yes",
			wantRefreshExpiresSub: "(in ",
		},
		{
			name: "refresh token itself has expired",
			tok: &token.Token{
				AccessToken:            "a",
				AccessTokenExpiration:  time.Now().Add(-2 * time.Hour).Format(time.RFC3339),
				RefreshToken:           "r",
				RefreshTokenExpiration: time.Now().Add(-time.Hour).Format(time.RFC3339),
			},
			wantStatus:            "expired",
			wantRefresh:           "yes",
			wantRefreshExpiresSub: "ago",
		},
		{
			name:                  "expired, has refresh token",
			tok:                   &token.Token{AccessToken: "a", AccessTokenExpiration: time.Now().Add(-2 * time.Hour).Format(time.RFC3339), RefreshToken: "r"},
			wantStatus:            "expired",
			wantExpiresSub:        "ago",
			wantRefresh:           "yes",
			wantRefreshExpiresSub: "unknown",
		},
		{
			name:                  "expired, no refresh token",
			tok:                   &token.Token{AccessToken: "a", AccessTokenExpiration: time.Now().Add(-2 * time.Hour).Format(time.RFC3339)},
			wantStatus:            "expired",
			wantExpiresSub:        "ago",
			wantRefresh:           "no",
			wantRefreshExpiresSub: "-",
		},
		{
			name:                  "unparseable expiration",
			tok:                   &token.Token{AccessToken: "a", AccessTokenExpiration: "not-a-time", RefreshToken: "r"},
			wantStatus:            "unknown",
			wantExpiresSub:        "invalid expiration",
			wantRefresh:           "yes",
			wantRefreshExpiresSub: "unknown",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, expires, refresh, refreshExpires := formatAccountStatus(tc.tok, tc.loadErr)
			if status != tc.wantStatus {
				t.Errorf("status = %q, want %q", status, tc.wantStatus)
			}
			if tc.wantExpiresSub != "" && !strings.Contains(expires, tc.wantExpiresSub) {
				t.Errorf("expires = %q, want substring %q", expires, tc.wantExpiresSub)
			}
			if refresh != tc.wantRefresh {
				t.Errorf("refresh = %q, want %q", refresh, tc.wantRefresh)
			}
			if tc.wantRefreshExpiresSub != "" && !strings.Contains(refreshExpires, tc.wantRefreshExpiresSub) {
				t.Errorf("refreshExpires = %q, want substring %q", refreshExpires, tc.wantRefreshExpiresSub)
			}
		})
	}
}

func TestRunStatusCommandAllAccounts(t *testing.T) {
	withXDGConfig(t, `
accounts:
  valid@gmail.com:
    provider: google
  fresh@gmail.com:
    provider: google
`)
	keyring.MockInit()

	if err := token.Store("valid@gmail.com", &token.Token{
		AccessToken:           "tok",
		AccessTokenExpiration: time.Now().Add(time.Hour).Format(time.RFC3339),
		RefreshToken:          "r",
	}); err != nil {
		t.Fatal(err)
	}
	// fresh@gmail.com has no stored token at all.

	out := captureStdout(t, func() {
		if err := run(&Args{Command: CmdStatus}); err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected header + 2 rows, got %d lines:\n%s", len(lines), out)
	}
	if !strings.HasPrefix(lines[0], "ACCOUNT") {
		t.Errorf("expected header row, got %q", lines[0])
	}
	// Accounts should be sorted: fresh@gmail.com before valid@gmail.com.
	if !strings.Contains(lines[1], "fresh@gmail.com") || !strings.Contains(lines[1], "not authorized") {
		t.Errorf("row 1 = %q, want fresh@gmail.com / not authorized", lines[1])
	}
	if !strings.Contains(lines[2], "valid@gmail.com") || !strings.Contains(lines[2], "valid") {
		t.Errorf("row 2 = %q, want valid@gmail.com / valid", lines[2])
	}
}

func TestRunStatusCommandSingleAccount(t *testing.T) {
	withXDGConfig(t, testConfigYAML)
	keyring.MockInit()

	out := captureStdout(t, func() {
		if err := run(&Args{Command: CmdStatus, Account: "me@gmail.com"}); err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected header + 1 row, got %d lines:\n%s", len(lines), out)
	}
	if !strings.Contains(lines[1], "me@gmail.com") {
		t.Errorf("row = %q, want it to mention me@gmail.com", lines[1])
	}
}

func TestRunStatusCommandUnknownAccount(t *testing.T) {
	withXDGConfig(t, testConfigYAML)
	keyring.MockInit()

	err := run(&Args{Command: CmdStatus, Account: "nobody@gmail.com"})
	if err == nil {
		t.Fatal("expected error for unknown account")
	}
}

func TestDaemonRefreshDue(t *testing.T) {
	cases := []struct {
		name    string
		tok     *token.Token
		wantDue bool
	}{
		{"no access token stored", &token.Token{}, true},
		{"already expired", &token.Token{AccessToken: "a", AccessTokenExpiration: time.Now().Add(-time.Minute).Format(time.RFC3339)}, true},
		{"expiring within lookahead", &token.Token{AccessToken: "a", AccessTokenExpiration: time.Now().Add(2 * time.Minute).Format(time.RFC3339)}, true},
		{"exactly at lookahead boundary", &token.Token{AccessToken: "a", AccessTokenExpiration: time.Now().Add(daemonExpiryLookahead).Format(time.RFC3339)}, true},
		{"comfortably valid", &token.Token{AccessToken: "a", AccessTokenExpiration: time.Now().Add(time.Hour).Format(time.RFC3339)}, false},
		{"unparseable expiration", &token.Token{AccessToken: "a", AccessTokenExpiration: "not-a-time"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			due, reason := daemonRefreshDue(tc.tok)
			if due != tc.wantDue {
				t.Errorf("due = %v, want %v (reason: %s)", due, tc.wantDue, reason)
			}
			if reason == "" {
				t.Error("expected a non-empty reason")
			}
		})
	}
}

func TestDaemonInterval(t *testing.T) {
	t.Run("defaults when unset", func(t *testing.T) {
		cfg := &config.Config{Global: &config.GlobalSection{}}
		out := captureStdout(t, func() {
			d, err := daemonInterval(cfg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if d != defaultDaemonInterval {
				t.Errorf("interval = %v, want default %v", d, defaultDaemonInterval)
			}
		})
		if !strings.Contains(out, "defaulting to") {
			t.Errorf("expected a NOTICE about defaulting, got: %s", out)
		}
	})

	t.Run("uses configured value", func(t *testing.T) {
		cfg := &config.Config{Global: &config.GlobalSection{Daemon: &config.DaemonConfig{Interval: "90s"}}}
		d, err := daemonInterval(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if d != 90*time.Second {
			t.Errorf("interval = %v, want 90s", d)
		}
	})

	t.Run("rejects unparseable value", func(t *testing.T) {
		cfg := &config.Config{Global: &config.GlobalSection{Daemon: &config.DaemonConfig{Interval: "not-a-duration"}}}
		if _, err := daemonInterval(cfg); err == nil {
			t.Fatal("expected error for unparseable interval")
		}
	})

	t.Run("rejects non-positive value", func(t *testing.T) {
		cfg := &config.Config{Global: &config.GlobalSection{Daemon: &config.DaemonConfig{Interval: "0s"}}}
		if _, err := daemonInterval(cfg); err == nil {
			t.Fatal("expected error for zero interval")
		}
	})
}

func TestDaemonTickRefreshesExpiringTokenAndLogsIt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "brand-new-access-token",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	withXDGConfig(t, `
global:
  storage: keyring
  google:
    token_endpoint: `+srv.URL+`
    scope: https://mail.google.com/
    client_id: cid
    client_secret: csecret
    sasl_method: OAUTHBEARER
accounts:
  me@gmail.com:
    provider: google
`)
	keyring.MockInit()

	if err := token.Store("me@gmail.com", &token.Token{
		AccessToken:           "about-to-expire",
		AccessTokenExpiration: time.Now().Add(2 * time.Minute).Format(time.RFC3339), // within daemonExpiryLookahead
		RefreshToken:          "refresh-abc",
	}); err != nil {
		t.Fatal(err)
	}

	cfgPath, err := config.LocateConfigFile("omt")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		daemonTick(newHTTPClient(&Args{}), cfg, []string{"me@gmail.com"}, false)
	})
	if !strings.Contains(out, "refreshed me@gmail.com") {
		t.Errorf("expected a refresh line, got: %s", out)
	}

	stored, err := token.Load("me@gmail.com")
	if err != nil {
		t.Fatal(err)
	}
	if stored.AccessToken != "brand-new-access-token" {
		t.Errorf("stored access token = %q, want the refreshed one", stored.AccessToken)
	}
}

func TestDaemonTickPrintsErrorOnRefreshFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"error":             "invalid_grant",
			"error_description": "Token has been expired or revoked.",
		})
	}))
	defer srv.Close()

	withXDGConfig(t, `
global:
  storage: keyring
  google:
    token_endpoint: `+srv.URL+`
    scope: https://mail.google.com/
    client_id: cid
    client_secret: csecret
    sasl_method: OAUTHBEARER
accounts:
  broken@gmail.com:
    provider: google
`)
	keyring.MockInit()

	if err := token.Store("broken@gmail.com", &token.Token{
		AccessToken:           "about-to-expire",
		AccessTokenExpiration: time.Now().Add(time.Minute).Format(time.RFC3339),
		RefreshToken:          "refresh-for-broken",
	}); err != nil {
		t.Fatal(err)
	}

	cfgPath, err := config.LocateConfigFile("omt")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		daemonTick(newHTTPClient(&Args{}), cfg, []string{"broken@gmail.com"}, false)
	})
	if !strings.Contains(out, "ERROR:") || !strings.Contains(out, "broken@gmail.com") {
		t.Errorf("expected an ERROR line mentioning broken@gmail.com, got: %s", out)
	}
}

func TestDaemonTickSilentForUnauthorizedAccountUnlessDebug(t *testing.T) {
	withXDGConfig(t, `
accounts:
  never-authorized@gmail.com:
    provider: google
`)
	keyring.MockInit()

	cfgPath, err := config.LocateConfigFile("omt")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	client := newHTTPClient(&Args{})

	out := captureStdout(t, func() {
		daemonTick(client, cfg, []string{"never-authorized@gmail.com"}, false)
	})
	if out != "" {
		t.Errorf("expected no output without debug, got: %q", out)
	}

	out = captureStdout(t, func() {
		daemonTick(client, cfg, []string{"never-authorized@gmail.com"}, true)
	})
	if !strings.Contains(out, "not authorized yet") {
		t.Errorf("expected a debug line about not-authorized, got: %s", out)
	}
}

func TestDaemonTickSkipsValidTokenSilentlyUnlessDebug(t *testing.T) {
	withXDGConfig(t, `
accounts:
  me@gmail.com:
    provider: google
`)
	keyring.MockInit()

	if err := token.Store("me@gmail.com", &token.Token{
		AccessToken:           "still-valid",
		AccessTokenExpiration: time.Now().Add(time.Hour).Format(time.RFC3339),
		RefreshToken:          "refresh-abc",
	}); err != nil {
		t.Fatal(err)
	}

	cfgPath, err := config.LocateConfigFile("omt")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	client := newHTTPClient(&Args{})

	out := captureStdout(t, func() {
		daemonTick(client, cfg, []string{"me@gmail.com"}, false)
	})
	if out != "" {
		t.Errorf("expected no output for a still-valid token without debug, got: %q", out)
	}

	out = captureStdout(t, func() {
		daemonTick(client, cfg, []string{"me@gmail.com"}, true)
	})
	if !strings.Contains(out, "no refresh needed") {
		t.Errorf("expected a debug line about no refresh needed, got: %s", out)
	}
}

func trimTrailingNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
