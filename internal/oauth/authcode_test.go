// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

package oauth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/schretzi/oauthmailtoken/internal/config"
)

func TestBuildAuthorizeURL(t *testing.T) {
	provider := config.ProviderConfig{
		AuthorizeEndpoint: "https://example.com/auth",
		ClientID:          "cid",
		Scope:             "scope one two",
	}
	got, err := BuildAuthorizeURL(provider, "me@example.com", "http://localhost:1234/", "chal")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("resulting URL does not parse: %v", err)
	}
	if u.Scheme+"://"+u.Host+u.Path != "https://example.com/auth" {
		t.Errorf("unexpected base URL: %s", got)
	}
	// Spaces in the scope must be percent-encoded as %20, not "+".
	if !strings.Contains(got, "scope=scope%20one%20two") {
		t.Errorf("expected %%20-encoded scope in %s", got)
	}

	q := u.Query()
	if q.Get("client_id") != "cid" {
		t.Errorf("client_id = %q", q.Get("client_id"))
	}
	if q.Get("login_hint") != "me@example.com" {
		t.Errorf("login_hint = %q", q.Get("login_hint"))
	}
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q", q.Get("response_type"))
	}
	if q.Get("code_challenge") != "chal" || q.Get("code_challenge_method") != "S256" {
		t.Errorf("unexpected PKCE params: %v", q)
	}
	if q.Get("tenant") != "" {
		t.Errorf("tenant should be absent when provider has none, got %q", q.Get("tenant"))
	}
}

func TestBuildAuthorizeURLIncludesTenant(t *testing.T) {
	provider := config.ProviderConfig{
		AuthorizeEndpoint: "https://example.com/auth",
		ClientID:          "cid",
		Tenant:            "common",
		Scope:             "scope",
	}
	got, err := BuildAuthorizeURL(provider, "me@example.com", "http://localhost/", "chal")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(got)
	if u.Query().Get("tenant") != "common" {
		t.Errorf("expected tenant=common in %s", got)
	}
}

func TestExchangeAuthCode(t *testing.T) {
	var gotBody url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		gotBody = r.PostForm
		writeJSON(t, w, map[string]any{
			"access_token":  "at",
			"refresh_token": "rt",
			"expires_in":    3600,
		})
	}))
	defer srv.Close()

	provider := config.ProviderConfig{
		TokenEndpoint: srv.URL,
		ClientID:      "cid",
		ClientSecret:  "secret",
		Scope:         "scope",
		Tenant:        "common",
	}
	tr, err := ExchangeAuthCode(t.Context(), srv.Client(), provider, "authcode123", "verifier123", "http://localhost:1/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tr.AccessToken != "at" || tr.RefreshToken != "rt" || tr.ExpiresInSeconds() != 3600 {
		t.Errorf("unexpected token response: %+v", tr)
	}
	if gotBody.Get("grant_type") != "authorization_code" {
		t.Errorf("grant_type = %q", gotBody.Get("grant_type"))
	}
	if gotBody.Get("code") != "authcode123" {
		t.Errorf("code = %q", gotBody.Get("code"))
	}
	if gotBody.Get("code_verifier") != "verifier123" {
		t.Errorf("code_verifier = %q", gotBody.Get("code_verifier"))
	}
	if gotBody.Get("tenant") != "common" {
		t.Errorf("tenant = %q", gotBody.Get("tenant"))
	}
}

func TestExchangeAuthCodeOmitsClientSecretForPublicClients(t *testing.T) {
	// Public clients - e.g. a well-known native-app client ID with no secret
	// registered, like Thunderbird's - must not send client_secret at all;
	// some token endpoints treat an empty value as an (invalid) provided
	// secret rather than "no secret".
	var gotBody url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		gotBody = r.PostForm
		writeJSON(t, w, map[string]any{"access_token": "at", "expires_in": 3600})
	}))
	defer srv.Close()

	provider := config.ProviderConfig{TokenEndpoint: srv.URL, ClientID: "cid"}
	if _, err := ExchangeAuthCode(t.Context(), srv.Client(), provider, "code", "verifier", "http://localhost/"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, present := gotBody["client_secret"]; present {
		t.Errorf("client_secret should be omitted entirely for a public client, got %q", gotBody.Get("client_secret"))
	}
}

func TestExchangeAuthCodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(t, w, map[string]any{
			"error":             "invalid_grant",
			"error_description": "code expired",
		})
	}))
	defer srv.Close()

	provider := config.ProviderConfig{TokenEndpoint: srv.URL}
	_, err := ExchangeAuthCode(t.Context(), srv.Client(), provider, "code", "verifier", "http://localhost/")
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.Code != "invalid_grant" {
		t.Errorf("Code = %q", apiErr.Code)
	}
}

func TestServeOnceReturnsCode(t *testing.T) {
	ln, err := ListenLocal(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	port := LocalPort(ln)

	resultCh := make(chan struct {
		code string
		err  error
	}, 1)
	go func() {
		code, err := ServeOnce(t.Context(), ln)
		resultCh <- struct {
			code string
			err  error
		}{code, err}
	}()

	resp, err := http.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/?code=thecode123")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	resp.Body.Close()

	select {
	case res := <-resultCh:
		if res.err != nil {
			t.Fatalf("ServeOnce returned error: %v", res.err)
		}
		if res.code != "thecode123" {
			t.Errorf("code = %q, want %q", res.code, "thecode123")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for ServeOnce")
	}
}

// TestServeOnceSurfacesRedirectError covers the case where the browser lands
// back on the loopback redirect URI with "error"/"error_description" instead
// of "code" - e.g. consent required, conditional access, or a tenant that
// rejects the app registration. The browser page still looks like a
// completed redirect either way, so ServeOnce must return a descriptive
// error instead of the generic "did not obtain an authcode" a caller would
// otherwise report for an empty code.
func TestServeOnceSurfacesRedirectError(t *testing.T) {
	ln, err := ListenLocal(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	port := LocalPort(ln)

	resultCh := make(chan struct {
		code string
		err  error
	}, 1)
	go func() {
		code, err := ServeOnce(t.Context(), ln)
		resultCh <- struct {
			code string
			err  error
		}{code, err}
	}()

	resp, err := http.Get("http://127.0.0.1:" + strconv.Itoa(port) +
		"/?error=access_denied&error_description=AADSTS50020%3A+user+account+from+identity+provider+does+not+exist")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	resp.Body.Close()

	select {
	case res := <-resultCh:
		if res.err == nil {
			t.Fatal("expected an error, got nil")
		}
		var apiErr *APIError
		if !errors.As(res.err, &apiErr) {
			t.Fatalf("expected *APIError, got %T: %v", res.err, res.err)
		}
		if apiErr.Code != "access_denied" {
			t.Errorf("Code = %q, want %q", apiErr.Code, "access_denied")
		}
		if !strings.Contains(apiErr.Description, "AADSTS50020") {
			t.Errorf("Description = %q, want it to contain AADSTS50020", apiErr.Description)
		}
		if res.code != "" {
			t.Errorf("code = %q, want empty", res.code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for ServeOnce")
	}
}
