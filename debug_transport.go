package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
)

// debugTransport wraps an http.RoundTripper and prints every response body
// it sees, mirroring the Python implementation's scattered
// "if args.debug: print(response)" calls after each token/device-code
// endpoint request - but in one place, for every request, instead of having
// to thread a debug flag through every HTTP call site.
type debugTransport struct {
	rt http.RoundTripper
}

func (d debugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := d.rt.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	body, rerr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if rerr != nil {
		return resp, err
	}
	fmt.Println(string(body))
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}
