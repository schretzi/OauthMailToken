// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

package oauth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/schretzi/oauthmailtoken/internal/config"
)

func TestRequestDeviceCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{
			"device_code":      "dc123",
			"user_code":        "ABCD-EFGH",
			"verification_uri": "https://example.com/device",
			"message":          "Go to https://example.com/device and enter ABCD-EFGH",
			"interval":         5,
			"expires_in":       900,
		})
	}))
	defer srv.Close()

	provider := config.ProviderConfig{DevicecodeEndpoint: srv.URL, ClientID: "cid", Scope: "scope"}
	dc, err := RequestDeviceCode(t.Context(), srv.Client(), provider)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dc.DeviceCode != "dc123" || dc.Interval != 5 {
		t.Errorf("unexpected device code response: %+v", dc)
	}
}

func TestPollDeviceTokenPendingThenSuccess(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		if attempts < 3 {
			writeJSON(t, w, map[string]any{"error": "authorization_pending"})
			return
		}
		writeJSON(t, w, map[string]any{
			"access_token": "at",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	provider := config.ProviderConfig{TokenEndpoint: srv.URL, ClientID: "cid", ClientSecret: "secret"}
	dc := DeviceCodeResponse{DeviceCode: "dc123", Interval: 0}

	var slept int
	sleep := func(time.Duration) { slept++ }
	var ticks int
	onTick := func() { ticks++ }

	tr, err := PollDeviceToken(t.Context(), srv.Client(), provider, dc, sleep, onTick)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tr.AccessToken != "at" {
		t.Errorf("AccessToken = %q", tr.AccessToken)
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
	if slept != 3 || ticks != 3 {
		t.Errorf("slept=%d ticks=%d, want 3/3", slept, ticks)
	}
}

func TestPollDeviceTokenDeclined(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{"error": "authorization_declined"})
	}))
	defer srv.Close()

	provider := config.ProviderConfig{TokenEndpoint: srv.URL}
	_, err := PollDeviceToken(t.Context(), srv.Client(), provider, DeviceCodeResponse{}, func(time.Duration) {}, nil)
	if !errors.Is(err, ErrAuthorizationDeclined) {
		t.Fatalf("expected ErrAuthorizationDeclined, got %v", err)
	}
}

func TestPollDeviceTokenExpired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{"error": "expired_token"})
	}))
	defer srv.Close()

	provider := config.ProviderConfig{TokenEndpoint: srv.URL}
	_, err := PollDeviceToken(t.Context(), srv.Client(), provider, DeviceCodeResponse{}, func(time.Duration) {}, nil)
	if !errors.Is(err, ErrDeviceCodeExpired) {
		t.Fatalf("expected ErrDeviceCodeExpired, got %v", err)
	}
}

func TestPollDeviceTokenOtherError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{"error": "invalid_client", "error_description": "bad secret"})
	}))
	defer srv.Close()

	provider := config.ProviderConfig{TokenEndpoint: srv.URL}
	_, err := PollDeviceToken(t.Context(), srv.Client(), provider, DeviceCodeResponse{}, func(time.Duration) {}, nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "invalid_client" {
		t.Fatalf("expected APIError invalid_client, got %v", err)
	}
}
