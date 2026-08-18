// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/schretzi/oauthmailtoken/internal/token"
)

// tokenEndpointConfig builds a config whose google provider points at srv.
func tokenEndpointConfig(srvURL string, accounts ...string) string {
	var b strings.Builder
	b.WriteString("global:\n  storage: keyring\n  keyring-backend: system\n  google:\n    token_endpoint: ")
	b.WriteString(srvURL)
	b.WriteString("\n    scope: https://mail.google.com/\n    client_id: cid\n    client_secret: csecret\n    sasl_method: OAUTHBEARER\naccounts:\n")
	for _, a := range accounts {
		b.WriteString("  " + a + ":\n    provider: google\n")
	}
	return b.String()
}

func TestRefreshCommandForcesRefreshEvenIfStillValid(t *testing.T) {
	var gotGrantType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		gotGrantType = r.PostForm.Get("grant_type")
		writeJSON(t, w, map[string]any{
			"access_token":             "brand-new-access-token",
			"refresh_token":            "brand-new-refresh-token",
			"expires_in":               3600,
			"refresh_token_expires_in": 7776000, // 90 days - some providers (not Google/MS) do send this
		})
	}))
	defer srv.Close()

	withXDGConfig(t, tokenEndpointConfig(srv.URL, "me@gmail.com"))
	keyring.MockInit()

	// Store a token that is still comfortably valid.
	if err := token.Store("me@gmail.com", &token.Token{
		AccessToken:           "still-valid-access-token",
		AccessTokenExpiration: time.Now().Add(time.Hour).Format(time.RFC3339),
		RefreshToken:          "old-refresh-token",
	}); err != nil {
		t.Fatal(err)
	}

	stdout, _, err := execute(t, "refresh", "me@gmail.com")
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}

	if gotGrantType != "refresh_token" {
		t.Errorf("grant_type = %q, want refresh_token", gotGrantType)
	}
	if got := trimTrailingNewline(stdout); got != "brand-new-access-token" {
		t.Errorf("stdout = %q, want exactly %q", stdout, "brand-new-access-token")
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

// A refresh token is a long-lived credential: it must not be echoed into the
// terminal (and into whatever captures stderr) unless explicitly asked for.
func TestRefreshTokenOnlyPrintedWithVerbose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{
			"access_token":  "new-access",
			"refresh_token": "super-secret-refresh-token",
			"expires_in":    3600,
		})
	}))
	defer srv.Close()

	for _, tc := range []struct {
		name       string
		argv       []string
		wantSecret bool
	}{
		{"default", []string{"refresh", "me@gmail.com"}, false},
		{"verbose", []string{"refresh", "-v", "me@gmail.com"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withXDGConfig(t, tokenEndpointConfig(srv.URL, "me@gmail.com"))
			keyring.MockInit()
			if err := token.Store("me@gmail.com", &token.Token{
				AccessToken:           "old",
				AccessTokenExpiration: time.Now().Add(time.Hour).Format(time.RFC3339),
				RefreshToken:          "old-refresh",
			}); err != nil {
				t.Fatal(err)
			}

			stdout, stderr, err := execute(t, tc.argv...)
			if err != nil {
				t.Fatalf("execute returned error: %v", err)
			}

			// Never on stdout, whatever the verbosity.
			if strings.Contains(stdout, "super-secret-refresh-token") {
				t.Errorf("refresh token leaked onto stdout: %q", stdout)
			}
			if got := strings.Contains(stderr, "super-secret-refresh-token"); got != tc.wantSecret {
				t.Errorf("refresh token on stderr = %v, want %v (stderr: %q)", got, tc.wantSecret, stderr)
			}

			// It must still be persisted either way.
			stored, err := token.Load("me@gmail.com")
			if err != nil {
				t.Fatal(err)
			}
			if stored.RefreshToken != "super-secret-refresh-token" {
				t.Errorf("stored refresh token = %q, want the new one", stored.RefreshToken)
			}
		})
	}
}

func TestRefreshCommandNoStoredToken(t *testing.T) {
	withXDGConfig(t, testConfigYAML)
	keyring.MockInit()

	if _, _, err := execute(t, "refresh", "me@gmail.com"); err == nil {
		t.Fatal("expected an error when no token is stored yet")
	}
}

func TestRefreshCommandAllAccounts(t *testing.T) {
	var refreshedAccounts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		refreshedAccounts = append(refreshedAccounts, r.PostForm.Get("refresh_token"))
		writeJSON(t, w, map[string]any{
			"access_token": "new-for-" + r.PostForm.Get("refresh_token"),
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	withXDGConfig(t, tokenEndpointConfig(srv.URL,
		"has-refresh@gmail.com", "not-authorized@gmail.com", "no-refresh-token@gmail.com"))
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

	stdout, _, err := execute(t, "refresh")
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}

	if len(refreshedAccounts) != 1 || refreshedAccounts[0] != "refresh-for-has-refresh" {
		t.Errorf("expected exactly one refresh call for has-refresh@gmail.com's refresh token, got %v", refreshedAccounts)
	}

	rows := lines(stdout)
	if len(rows) != 4 { // header + 3 accounts
		t.Fatalf("expected header + 3 rows, got %d lines:\n%s", len(rows), stdout)
	}
	joined := strings.Join(rows, "\n")
	for _, want := range []string{
		"has-refresh@gmail.com", "refreshed",
		"not-authorized@gmail.com", "skipped: not authorized",
		"no-refresh-token@gmail.com", "skipped: no refresh token",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("summary table missing %q, got:\n%s", want, stdout)
		}
	}

	stored, err := token.Load("has-refresh@gmail.com")
	if err != nil {
		t.Fatal(err)
	}
	if stored.AccessToken != "new-for-refresh-for-has-refresh" {
		t.Errorf("stored access token = %q, want the refreshed one", stored.AccessToken)
	}
}

func TestRefreshCommandAllAccountsReportsFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{
			"error":             "invalid_grant",
			"error_description": "Token has been expired or revoked.",
		})
	}))
	defer srv.Close()

	withXDGConfig(t, tokenEndpointConfig(srv.URL, "broken@gmail.com"))
	keyring.MockInit()

	if err := token.Store("broken@gmail.com", &token.Token{
		AccessToken:           "old-access",
		AccessTokenExpiration: time.Now().Add(time.Hour).Format(time.RFC3339),
		RefreshToken:          "refresh-for-broken",
	}); err != nil {
		t.Fatal(err)
	}

	stdout, _, err := execute(t, "refresh")
	if err == nil {
		t.Fatal("expected an error when a refresh attempt fails")
	}
	if !strings.Contains(stdout, "broken@gmail.com") || !strings.Contains(stdout, "error:") {
		t.Errorf("expected an error row for broken@gmail.com, got:\n%s", stdout)
	}
}

func TestRefreshCommandRejectsExtraArguments(t *testing.T) {
	withXDGConfig(t, testConfigYAML)
	keyring.MockInit()

	_, _, err := execute(t, "refresh", "a@gmail.com", "b@gmail.com")
	assertUsageError(t, err)
}
