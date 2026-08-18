// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/schretzi/oauthmailtoken/internal/config"
)

// ErrAuthorizationDeclined is returned by PollDeviceToken when the user
// declined the authorization request.
var ErrAuthorizationDeclined = errors.New("authorization declined by user")

// ErrDeviceCodeExpired is returned by PollDeviceToken when the device code
// expired before the user completed authorization.
var ErrDeviceCodeExpired = errors.New("device code expired before authorization completed")

// DeviceCodeResponse models the JSON body returned by an OAuth2 device
// authorization endpoint.
type DeviceCodeResponse struct {
	DeviceCode      string  `json:"device_code"`
	UserCode        string  `json:"user_code"`
	VerificationURI string  `json:"verification_uri"`
	Message         string  `json:"message"`
	Interval        flexInt `json:"interval"`
	ExpiresIn       flexInt `json:"expires_in"`

	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// RequestDeviceCode starts the OAuth2 device-code flow by requesting a
// device/user code pair from provider.DevicecodeEndpoint.
func RequestDeviceCode(ctx context.Context, client *http.Client, provider config.ProviderConfig) (DeviceCodeResponse, error) {
	params := url.Values{}
	params.Set("client_id", provider.ClientID)
	if provider.Tenant != "" {
		params.Set("tenant", provider.Tenant)
	}
	params.Set("scope", provider.Scope)

	body, _, err := postFormRaw(ctx, client, provider.DevicecodeEndpoint, params)
	if err != nil {
		return DeviceCodeResponse{}, err
	}

	var dc DeviceCodeResponse
	if err := json.Unmarshal(body, &dc); err != nil {
		return DeviceCodeResponse{}, fmt.Errorf("decoding device code response: %w (body=%q)", err, body)
	}
	if dc.Error != "" {
		return dc, &APIError{Code: dc.Error, Description: dc.ErrorDescription}
	}
	return dc, nil
}

// PollDeviceToken polls provider.TokenEndpoint until the user completes
// authorization (or it fails). sleep is called with the poll interval before
// every attempt (including the first), and onTick (if non-nil) is called
// after each sleep, before the request - both are injectable so tests don't
// need to wait in real time.
//
// Polling stops as soon as ctx is cancelled, so an interrupted device-code
// flow doesn't keep hammering the token endpoint.
func PollDeviceToken(ctx context.Context, client *http.Client, provider config.ProviderConfig, dc DeviceCodeResponse, sleep func(time.Duration), onTick func()) (TokenResponse, error) {
	params := url.Values{}
	params.Set("client_id", provider.ClientID)
	if provider.Tenant != "" {
		params.Set("tenant", provider.Tenant)
	}
	params.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	if provider.ClientSecret != "" {
		// Public clients (no client_secret configured - e.g. a well-known
		// native-app client ID like Thunderbird's) must omit this parameter
		// entirely rather than send it empty; some token endpoints treat an
		// empty client_secret as an (invalid) provided secret rather than
		// "none".
		params.Set("client_secret", provider.ClientSecret)
	}
	params.Set("device_code", dc.DeviceCode)

	interval := time.Duration(dc.Interval) * time.Second

	for {
		sleep(interval)
		if onTick != nil {
			onTick()
		}
		if err := ctx.Err(); err != nil {
			return TokenResponse{}, err
		}

		tr, _, err := postForm(ctx, client, provider.TokenEndpoint, params)
		if err == nil {
			return tr, nil
		}

		var apiErr *APIError
		if errors.As(err, &apiErr) {
			switch apiErr.Code {
			case "authorization_pending":
				continue
			case "authorization_declined":
				return TokenResponse{}, ErrAuthorizationDeclined
			case "expired_token":
				return TokenResponse{}, ErrDeviceCodeExpired
			default:
				return TokenResponse{}, apiErr
			}
		}
		return TokenResponse{}, err
	}
}
