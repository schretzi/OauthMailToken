// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

package oauth

import "testing"

func TestNewPKCEProducesUsableValues(t *testing.T) {
	p, err := NewPKCE()
	if err != nil {
		t.Fatalf("NewPKCE returned error: %v", err)
	}
	if len(p.Verifier) < 43 || len(p.Verifier) > 128 {
		t.Errorf("verifier length %d out of RFC 7636 range [43,128]", len(p.Verifier))
	}
	if p.Challenge != ChallengeFromVerifier(p.Verifier) {
		t.Errorf("challenge does not match verifier")
	}
}

func TestNewPKCEIsRandom(t *testing.T) {
	a, err := NewPKCE()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewPKCE()
	if err != nil {
		t.Fatal(err)
	}
	if a.Verifier == b.Verifier {
		t.Error("two calls to NewPKCE produced the same verifier")
	}
}

func TestChallengeFromVerifierKnownVector(t *testing.T) {
	// From RFC 7636 appendix B.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := ChallengeFromVerifier(verifier); got != want {
		t.Errorf("ChallengeFromVerifier(%q) = %q, want %q", verifier, got, want)
	}
}
