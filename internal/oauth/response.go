// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// flexInt unmarshals a JSON field that different OAuth2 servers may encode
// either as a number (3600) or as a numeric string ("3600").
type flexInt int

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("parsing integer field %q: %w", s, err)
	}
	*f = flexInt(n)
	return nil
}

// TokenResponse models the JSON body returned by an OAuth2 token endpoint.
type TokenResponse struct {
	AccessToken  string  `json:"access_token"`
	RefreshToken string  `json:"refresh_token"`
	ExpiresIn    flexInt `json:"expires_in"`
	// RefreshExpiresIn is the refresh token's own lifetime in seconds, if
	// the provider reports one. This isn't part of RFC 6749 and neither
	// Google nor Microsoft's endpoints send it for the flows this program
	// uses (their refresh tokens are effectively long-lived, valid until
	// revoked or unused for a long time, rather than carrying a fixed
	// expiry) - but some other providers (e.g. Keycloak, Okta) do, so it's
	// captured opportunistically when present.
	RefreshExpiresIn flexInt `json:"refresh_token_expires_in"`
	Error            string  `json:"error"`
	ErrorDescription string  `json:"error_description"`
}

// ExpiresInSeconds returns the access token's lifetime in seconds.
func (r TokenResponse) ExpiresInSeconds() int {
	return int(r.ExpiresIn)
}

// RefreshExpiresInSeconds returns the refresh token's own lifetime in
// seconds, or 0 if the provider didn't report one (the common case for
// Google/Microsoft - see RefreshExpiresIn).
func (r TokenResponse) RefreshExpiresInSeconds() int {
	return int(r.RefreshExpiresIn)
}

// APIError represents an OAuth2 "error"/"error_description" pair returned by
// an authorization or token endpoint.
type APIError struct {
	Code        string
	Description string
}

func (e *APIError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Description)
	}
	return e.Code
}

// postFormRaw POSTs params as application/x-www-form-urlencoded to endpoint
// and returns the raw response body together with the HTTP status code.
//
// Every OAuth2 request this package makes goes through here, so they all
// carry the caller's context - which is what lets Ctrl-C (and the daemon's
// SIGTERM handler) abort a request against a slow or wedged token endpoint
// instead of waiting out the client timeout.
func postFormRaw(ctx context.Context, client *http.Client, endpoint string, params url.Values) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, 0, fmt.Errorf("building request for %s: %w", endpoint, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

// postForm POSTs params as application/x-www-form-urlencoded to endpoint and
// decodes the JSON response body. If the response contains an "error" field,
// it returns the decoded body together with an *APIError. If the HTTP status
// indicates failure but no "error" field was present, it returns a generic
// error describing the unexpected response.
func postForm(ctx context.Context, client *http.Client, endpoint string, params url.Values) (TokenResponse, int, error) {
	body, status, err := postFormRaw(ctx, client, endpoint, params)
	if err != nil {
		return TokenResponse{}, status, err
	}

	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return TokenResponse{}, status, fmt.Errorf("decoding response from %s: %w (body=%q)", endpoint, err, body)
	}

	if tr.Error != "" {
		return tr, status, &APIError{Code: tr.Error, Description: tr.ErrorDescription}
	}
	if status >= http.StatusBadRequest {
		return tr, status, fmt.Errorf("%s returned HTTP %d: %s", endpoint, status, body)
	}
	if tr.AccessToken == "" {
		// A 200-ish response with neither an "error" field nor an
		// "access_token" - e.g. a provider that responds with an unexpected
		// body shape, an interstitial/consent page rendered as 200 instead
		// of a proper OAuth2 error, or a misconfigured endpoint URL. Treat
		// it as a failure instead of silently continuing with an empty
		// access token, which would otherwise get stored and printed as a
		// blank line with no indication anything went wrong.
		return tr, status, fmt.Errorf("%s returned no access_token (and no error) - response: %s", endpoint, body)
	}
	return tr, status, nil
}
