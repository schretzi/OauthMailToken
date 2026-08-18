// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

package oauth

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/schretzi/oauthmailtoken/internal/config"
)

// BuildAuthorizeURL builds the browser-facing authorization URL for the
// "authcode"/"localhostauthcode" flow.
func BuildAuthorizeURL(provider config.ProviderConfig, account, redirectURI, codeChallenge string) (string, error) {
	base, err := url.Parse(provider.AuthorizeEndpoint)
	if err != nil {
		return "", fmt.Errorf("parsing authorize_endpoint: %w", err)
	}

	q := url.Values{}
	q.Set("client_id", provider.ClientID)
	if provider.Tenant != "" {
		q.Set("tenant", provider.Tenant)
	}
	q.Set("scope", provider.Scope)
	q.Set("login_hint", account)
	q.Set("response_type", "code")
	q.Set("redirect_uri", redirectURI)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")

	// Percent-encode spaces as %20 (matching Python's
	// urlencode(..., quote_via=urllib.parse.quote)) rather than Go's default
	// of "+", which some authorization servers handle less predictably in a
	// browser-facing URL.
	base.RawQuery = strings.ReplaceAll(q.Encode(), "+", "%20")
	return base.String(), nil
}

// ExchangeAuthCode exchanges an authorization code (obtained via the
// authcode/localhostauthcode flow) for an access/refresh token.
func ExchangeAuthCode(ctx context.Context, client *http.Client, provider config.ProviderConfig, code, verifier, redirectURI string) (TokenResponse, error) {
	params := url.Values{}
	params.Set("client_id", provider.ClientID)
	if provider.Tenant != "" {
		params.Set("tenant", provider.Tenant)
	}
	params.Set("scope", provider.Scope)
	params.Set("redirect_uri", redirectURI)
	params.Set("grant_type", "authorization_code")
	params.Set("code", code)
	if provider.ClientSecret != "" {
		// See the comment in devicecode.go's PollDeviceToken: public clients
		// (no secret configured) must omit this parameter entirely.
		params.Set("client_secret", provider.ClientSecret)
	}
	params.Set("code_verifier", verifier)

	tr, _, err := postForm(ctx, client, provider.TokenEndpoint, params)
	return tr, err
}

// ListenLocal opens a loopback TCP listener on an OS-assigned free port, for
// use with ServeOnce in the "localhostauthcode" flow.
func ListenLocal(ctx context.Context) (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(ctx, "tcp", "127.0.0.1:0")
}

// LocalPort returns the port ListenLocal bound to, or 0 if ln is not a TCP
// listener (which cannot happen for a listener ListenLocal returned).
func LocalPort(ln net.Listener) int {
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		return 0
	}
	return addr.Port
}

const redirectSuccessHTML = `<html><head><title>Authorization result</title></head>` +
	`<body><p>Authorization redirect completed. You may close this window.</p></body></html>`

// redirectFailureTemplate renders the page shown when the provider redirects
// back with an error instead of a code. It is an html/template rather than a
// fmt format string on purpose: the message it interpolates is built from
// the "error"/"error_description" query parameters, i.e. attacker-influenced
// input reflected straight back into the response, so it must be
// contextually escaped (gosec G705).
var redirectFailureTemplate = template.Must(template.New("redirect-failure").Parse(
	`<html><head><title>Authorization result</title></head>` +
		`<body><p>Authorization failed: {{.}}. You may close this window and check the terminal.</p></body></html>`))

// redirectReadHeaderTimeout bounds how long a client may take to send its
// request headers to the loopback redirect listener. In practice the only
// client is the local browser following one redirect, but leaving it
// unbounded makes the server a Slowloris target (gosec G112).
const redirectReadHeaderTimeout = 10 * time.Second

// redirectResult is what the loopback handler observed on the single
// redirect request it caught: either a "code" query parameter (success), or
// an "error"/"error_description" pair (the provider declined - e.g. consent
// required, conditional access, tenant restrictions).
type redirectResult struct {
	code    string
	errCode string
	errDesc string
}

// ServeOnce serves a single HTTP request on ln and extracts the OAuth2
// redirect parameters from it ("code" on success, "error"/"error_description"
// on failure). It mirrors the Python implementation's use of
// http.server.HTTPServer(...).handle_request() to catch exactly one OAuth2
// redirect from the browser.
//
// If the provider redirected back with an error instead of a code (which
// still looks like a normal, completed redirect in the browser - there's no
// generic way to show a scary failure page from the *authorization server's*
// redirect itself), ServeOnce returns a descriptive error instead of silently
// reporting "no code obtained".
func ServeOnce(ctx context.Context, ln net.Listener) (string, error) {
	resultCh := make(chan redirectResult, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		res := redirectResult{
			code:    q.Get("code"),
			errCode: q.Get("error"),
			errDesc: q.Get("error_description"),
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if res.errCode != "" {
			msg := res.errCode
			if res.errDesc != "" {
				msg = fmt.Sprintf("%s (%s)", res.errCode, res.errDesc)
			}
			// Best-effort: what matters is the result handed back below,
			// and the browser tab is about to be closed either way.
			_ = redirectFailureTemplate.Execute(w, msg)
		} else {
			fmt.Fprint(w, redirectSuccessHTML)
		}
		select {
		case resultCh <- res:
		default:
		}
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: redirectReadHeaderTimeout}
	serveErrCh := make(chan error, 1)
	go func() { serveErrCh <- srv.Serve(ln) }()

	select {
	case res := <-resultCh:
		_ = srv.Close()
		if res.errCode != "" {
			return "", &APIError{Code: res.errCode, Description: res.errDesc}
		}
		return res.code, nil
	case err := <-serveErrCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return "", err
		}
		return "", errors.New("local redirect server closed before a code was received")
	case <-ctx.Done():
		_ = srv.Close()
		return "", ctx.Err()
	}
}
