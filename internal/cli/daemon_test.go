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

	"github.com/schretzi/oauthmailtoken/internal/config"
	"github.com/schretzi/oauthmailtoken/internal/token"
)

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
		a, stdout, _ := newTestApp(false)
		cfg := &config.Config{Global: &config.GlobalSection{}}

		d, err := a.daemonInterval(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if d != defaultDaemonInterval {
			t.Errorf("interval = %v, want default %v", d, defaultDaemonInterval)
		}
		if !strings.Contains(stdout.String(), "defaulting to") {
			t.Errorf("expected a NOTICE about defaulting, got: %s", stdout)
		}
	})

	t.Run("uses configured value", func(t *testing.T) {
		a, _, _ := newTestApp(false)
		cfg := &config.Config{Global: &config.GlobalSection{Daemon: &config.DaemonConfig{Interval: "90s"}}}

		d, err := a.daemonInterval(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if d != 90*time.Second {
			t.Errorf("interval = %v, want 90s", d)
		}
	})

	t.Run("rejects unparseable value", func(t *testing.T) {
		a, _, _ := newTestApp(false)
		cfg := &config.Config{Global: &config.GlobalSection{Daemon: &config.DaemonConfig{Interval: "not-a-duration"}}}
		if _, err := a.daemonInterval(cfg); err == nil {
			t.Fatal("expected an error for an unparseable interval")
		}
	})

	t.Run("rejects non-positive value", func(t *testing.T) {
		a, _, _ := newTestApp(false)
		cfg := &config.Config{Global: &config.GlobalSection{Daemon: &config.DaemonConfig{Interval: "0s"}}}
		if _, err := a.daemonInterval(cfg); err == nil {
			t.Fatal("expected an error for a zero interval")
		}
	})
}

func TestDaemonCommandRejectsAnAccountArgument(t *testing.T) {
	withXDGConfig(t, testConfigYAML)
	keyring.MockInit()

	_, _, err := execute(t, "daemon", "me@gmail.com")
	assertUsageError(t, err)
}

func TestDaemonTickRefreshesExpiringTokenAndLogsIt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{
			"access_token": "brand-new-access-token",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	withXDGConfig(t, tokenEndpointConfig(srv.URL, "me@gmail.com"))
	keyring.MockInit()

	if err := token.Store("me@gmail.com", &token.Token{
		AccessToken:           "about-to-expire",
		AccessTokenExpiration: time.Now().Add(2 * time.Minute).Format(time.RFC3339), // within daemonExpiryLookahead
		RefreshToken:          "refresh-abc",
	}); err != nil {
		t.Fatal(err)
	}

	a, stdout, _ := newTestApp(false)
	a.daemonTick(t.Context(), a.httpClient(), loadTestConfig(t), []string{"me@gmail.com"}, false)

	if !strings.Contains(stdout.String(), "refreshed me@gmail.com") {
		t.Errorf("expected a refresh line, got: %s", stdout)
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
		AccessToken:           "about-to-expire",
		AccessTokenExpiration: time.Now().Add(time.Minute).Format(time.RFC3339),
		RefreshToken:          "refresh-for-broken",
	}); err != nil {
		t.Fatal(err)
	}

	a, stdout, _ := newTestApp(false)
	a.daemonTick(t.Context(), a.httpClient(), loadTestConfig(t), []string{"broken@gmail.com"}, false)

	out := stdout.String()
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
	cfg := loadTestConfig(t)

	a, stdout, _ := newTestApp(false)
	a.daemonTick(t.Context(), a.httpClient(), cfg, []string{"never-authorized@gmail.com"}, false)
	if stdout.String() != "" {
		t.Errorf("expected no output without debug, got: %q", stdout)
	}

	a, stdout, _ = newTestApp(true)
	a.daemonTick(t.Context(), a.httpClient(), cfg, []string{"never-authorized@gmail.com"}, true)
	if !strings.Contains(stdout.String(), "not authorized yet") {
		t.Errorf("expected a debug line about not-authorized, got: %s", stdout)
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
	cfg := loadTestConfig(t)

	a, stdout, _ := newTestApp(false)
	a.daemonTick(t.Context(), a.httpClient(), cfg, []string{"me@gmail.com"}, false)
	if stdout.String() != "" {
		t.Errorf("expected no output for a still-valid token without debug, got: %q", stdout)
	}

	a, stdout, _ = newTestApp(true)
	a.daemonTick(t.Context(), a.httpClient(), cfg, []string{"me@gmail.com"}, true)
	if !strings.Contains(stdout.String(), "no refresh needed") {
		t.Errorf("expected a debug line about no refresh needed, got: %s", stdout)
	}
}
