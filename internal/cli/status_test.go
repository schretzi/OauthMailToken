// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

package cli

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/schretzi/oauthmailtoken/internal/token"
)

func TestStatusCommandAllAccounts(t *testing.T) {
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

	stdout, _, err := execute(t, "status")
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}

	rows := lines(stdout)
	if len(rows) != 3 {
		t.Fatalf("expected header + 2 rows, got %d lines:\n%s", len(rows), stdout)
	}
	if !strings.HasPrefix(rows[0], "ACCOUNT") {
		t.Errorf("expected header row, got %q", rows[0])
	}
	// Accounts should be sorted: fresh@gmail.com before valid@gmail.com.
	if !strings.Contains(rows[1], "fresh@gmail.com") || !strings.Contains(rows[1], statusNotAuthorized) {
		t.Errorf("row 1 = %q, want fresh@gmail.com / not authorized", rows[1])
	}
	if !strings.Contains(rows[2], "valid@gmail.com") || !strings.Contains(rows[2], statusValid) {
		t.Errorf("row 2 = %q, want valid@gmail.com / valid", rows[2])
	}
}

func TestStatusCommandSingleAccount(t *testing.T) {
	withXDGConfig(t, testConfigYAML)
	keyring.MockInit()

	stdout, _, err := execute(t, "status", "me@gmail.com")
	if err != nil {
		t.Fatalf("execute returned error: %v", err)
	}

	rows := lines(stdout)
	if len(rows) != 2 {
		t.Fatalf("expected header + 1 row, got %d lines:\n%s", len(rows), stdout)
	}
	if !strings.Contains(rows[1], "me@gmail.com") {
		t.Errorf("row = %q, want it to mention me@gmail.com", rows[1])
	}
}

func TestStatusCommandUnknownAccount(t *testing.T) {
	withXDGConfig(t, testConfigYAML)
	keyring.MockInit()

	if _, _, err := execute(t, "status", "nobody@gmail.com"); !errors.Is(err, errUnknownAccount) {
		t.Fatalf("err = %v, want errUnknownAccount", err)
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
			wantStatus:            statusError,
			wantExpiresSub:        "keyring unavailable",
			wantRefresh:           valueNone,
			wantRefreshExpiresSub: valueNone,
		},
		{
			name:                  "never authorized",
			tok:                   nil,
			wantStatus:            statusNotAuthorized,
			wantRefresh:           valueNone,
			wantRefreshExpiresSub: valueNone,
		},
		{
			name:                  "valid, has refresh token, provider didn't report its expiry",
			tok:                   &token.Token{AccessToken: "a", AccessTokenExpiration: time.Now().Add(30 * time.Minute).Format(time.RFC3339), RefreshToken: "r"},
			wantStatus:            statusValid,
			wantExpiresSub:        "(in ",
			wantRefresh:           valueYes,
			wantRefreshExpiresSub: valueUnknown,
		},
		{
			name: "valid, refresh token has a known future expiry",
			tok: &token.Token{
				AccessToken:            "a",
				AccessTokenExpiration:  time.Now().Add(30 * time.Minute).Format(time.RFC3339),
				RefreshToken:           "r",
				RefreshTokenExpiration: time.Now().Add(90 * 24 * time.Hour).Format(time.RFC3339),
			},
			wantStatus:            statusValid,
			wantRefresh:           valueYes,
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
			wantStatus:            statusExpired,
			wantRefresh:           valueYes,
			wantRefreshExpiresSub: "ago",
		},
		{
			name:                  "expired, has refresh token",
			tok:                   &token.Token{AccessToken: "a", AccessTokenExpiration: time.Now().Add(-2 * time.Hour).Format(time.RFC3339), RefreshToken: "r"},
			wantStatus:            statusExpired,
			wantExpiresSub:        "ago",
			wantRefresh:           valueYes,
			wantRefreshExpiresSub: valueUnknown,
		},
		{
			name:                  "expired, no refresh token",
			tok:                   &token.Token{AccessToken: "a", AccessTokenExpiration: time.Now().Add(-2 * time.Hour).Format(time.RFC3339)},
			wantStatus:            statusExpired,
			wantExpiresSub:        "ago",
			wantRefresh:           valueNo,
			wantRefreshExpiresSub: valueNone,
		},
		{
			name:                  "unparseable expiration",
			tok:                   &token.Token{AccessToken: "a", AccessTokenExpiration: "not-a-time", RefreshToken: "r"},
			wantStatus:            statusUnknown,
			wantExpiresSub:        valueInvalidExpiration,
			wantRefresh:           valueYes,
			wantRefreshExpiresSub: valueUnknown,
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
