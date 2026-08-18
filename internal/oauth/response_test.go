// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestTokenResponseDecodesRefreshExpiresIn(t *testing.T) {
	body := `{"access_token":"a","expires_in":3600,"refresh_token":"r","refresh_token_expires_in":7776000}`
	var tr TokenResponse
	if err := json.Unmarshal([]byte(body), &tr); err != nil {
		t.Fatalf("unmarshal returned error: %v", err)
	}
	if tr.ExpiresInSeconds() != 3600 {
		t.Errorf("ExpiresInSeconds() = %d, want 3600", tr.ExpiresInSeconds())
	}
	if tr.RefreshExpiresInSeconds() != 7776000 {
		t.Errorf("RefreshExpiresInSeconds() = %d, want 7776000", tr.RefreshExpiresInSeconds())
	}
}

func TestTokenResponseDecodesRefreshExpiresInAsString(t *testing.T) {
	// Some servers send integers as quoted strings; flexInt should handle both.
	body := `{"access_token":"a","expires_in":"3600","refresh_token_expires_in":"7776000"}`
	var tr TokenResponse
	if err := json.Unmarshal([]byte(body), &tr); err != nil {
		t.Fatalf("unmarshal returned error: %v", err)
	}
	if tr.ExpiresInSeconds() != 3600 {
		t.Errorf("ExpiresInSeconds() = %d, want 3600", tr.ExpiresInSeconds())
	}
	if tr.RefreshExpiresInSeconds() != 7776000 {
		t.Errorf("RefreshExpiresInSeconds() = %d, want 7776000", tr.RefreshExpiresInSeconds())
	}
}

func TestTokenResponseWithoutRefreshExpiresInDefaultsToZero(t *testing.T) {
	body := `{"access_token":"a","expires_in":3600,"refresh_token":"r"}`
	var tr TokenResponse
	if err := json.Unmarshal([]byte(body), &tr); err != nil {
		t.Fatalf("unmarshal returned error: %v", err)
	}
	if tr.RefreshExpiresInSeconds() != 0 {
		t.Errorf("RefreshExpiresInSeconds() = %d, want 0 (not reported by provider)", tr.RefreshExpiresInSeconds())
	}
}

func TestPostFormNoAccessTokenNoErrorReturnsError(t *testing.T) {
	// Simulates a token endpoint that answers HTTP 200 with a body that has
	// neither "access_token" nor "error" - e.g. an interstitial/consent page
	// or an unexpected response shape. postForm must treat this as a failure
	// instead of silently returning a TokenResponse with an empty
	// AccessToken (which would previously get stored and printed as a blank
	// line with no indication anything went wrong).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	_, status, err := postForm(t.Context(), srv.Client(), srv.URL, url.Values{})
	if err == nil {
		t.Fatal("postForm returned nil error, want an error for a response with no access_token and no error field")
	}
	if !strings.Contains(err.Error(), "no access_token") {
		t.Errorf("postForm error = %q, want it to mention the missing access_token", err.Error())
	}
	if status != http.StatusOK {
		t.Errorf("postForm status = %d, want %d", status, http.StatusOK)
	}
}

func TestPostFormWithAccessTokenSucceeds(t *testing.T) {
	// Sanity check that the new empty-access-token guard doesn't reject a
	// normal, successful response.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"a","expires_in":3600}`))
	}))
	defer srv.Close()

	tr, status, err := postForm(t.Context(), srv.Client(), srv.URL, url.Values{})
	if err != nil {
		t.Fatalf("postForm returned error: %v", err)
	}
	if tr.AccessToken != "a" {
		t.Errorf("AccessToken = %q, want %q", tr.AccessToken, "a")
	}
	if status != http.StatusOK {
		t.Errorf("postForm status = %d, want %d", status, http.StatusOK)
	}
}
