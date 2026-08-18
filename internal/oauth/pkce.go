// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// verifierBytes is the number of random bytes used for the PKCE code
// verifier, matching the Python implementation's secrets.token_urlsafe(90).
const verifierBytes = 90

// PKCE holds a PKCE code verifier and its S256 code challenge, as used by
// the OAuth2 "authorization code" flow (RFC 7636).
type PKCE struct {
	Verifier  string
	Challenge string
}

// NewPKCE generates a fresh, random PKCE verifier/challenge pair.
func NewPKCE() (PKCE, error) {
	buf := make([]byte, verifierBytes)
	if _, err := rand.Read(buf); err != nil {
		return PKCE{}, err
	}
	verifier := base64.RawURLEncoding.EncodeToString(buf)
	return PKCE{
		Verifier:  verifier,
		Challenge: ChallengeFromVerifier(verifier),
	}, nil
}

// ChallengeFromVerifier derives the S256 code challenge for a given verifier.
func ChallengeFromVerifier(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
