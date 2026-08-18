// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

package oauth

import (
	"encoding/json"
	"net/http"
	"testing"
)

// writeJSON encodes v as the JSON body of a stub OAuth2 endpoint response.
// It exists so the encode error is actually checked: a silent failure here
// would surface as a confusing "decoding response" error from the code under
// test rather than as a broken stub.
//
// It runs inside an httptest handler goroutine, so it reports with t.Errorf
// rather than t.Fatalf - the latter may only be called from the goroutine
// running the test.
func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("encoding stub response: %v", err)
	}
}
