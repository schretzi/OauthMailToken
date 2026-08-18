// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

package oauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/schretzi/oauthmailtoken/internal/config"
)

func TestExchangeRefreshTokenOmitsTenant(t *testing.T) {
	var gotBody url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		gotBody = r.PostForm
		writeJSON(t, w, map[string]any{
			"access_token": "at2",
			"expires_in":   1800,
		})
	}))
	defer srv.Close()

	provider := config.ProviderConfig{
		TokenEndpoint: srv.URL,
		ClientID:      "cid",
		ClientSecret:  "secret",
		Tenant:        "common", // must NOT be sent on refresh, matching the legacy Python behaviour
	}
	tr, err := ExchangeRefreshToken(t.Context(), srv.Client(), provider, "oldrefresh")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tr.AccessToken != "at2" || tr.ExpiresInSeconds() != 1800 {
		t.Errorf("unexpected token response: %+v", tr)
	}
	if gotBody.Get("grant_type") != "refresh_token" {
		t.Errorf("grant_type = %q", gotBody.Get("grant_type"))
	}
	if gotBody.Get("refresh_token") != "oldrefresh" {
		t.Errorf("refresh_token = %q", gotBody.Get("refresh_token"))
	}
	if gotBody.Has("tenant") {
		t.Errorf("tenant should not be sent on refresh, got %q", gotBody.Get("tenant"))
	}
}
