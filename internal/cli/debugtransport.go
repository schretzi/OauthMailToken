// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

package cli

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
)

// debugTransport wraps an http.RoundTripper and dumps every response body it
// sees to out, mirroring the Python implementation's scattered
// "if args.debug: print(response)" calls after each token/device-code
// endpoint request - but in one place, for every request, instead of having
// to thread a debug flag through every HTTP call site.
//
// out is the diagnostic stream, never the result stream: a raw token
// endpoint response must not end up in the output a caller pipes somewhere.
type debugTransport struct {
	rt  http.RoundTripper
	out io.Writer
}

func (d debugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := d.rt.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}

	body, rerr := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); cerr != nil && rerr == nil {
		rerr = cerr
	}
	if rerr != nil {
		// The body has been consumed and closed, so it is unusable. Report
		// the failure instead of handing back a silently-empty body the
		// caller would misparse. A RoundTripper must return either a
		// response or an error, never both.
		return nil, rerr
	}

	fmt.Fprintln(d.out, string(body))
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}
