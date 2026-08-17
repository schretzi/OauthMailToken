package token

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
)

func TestIsValidNil(t *testing.T) {
	var tok *Token
	if tok.IsValid() {
		t.Fatal("nil token should not be valid")
	}
}

func TestIsValidEmpty(t *testing.T) {
	tok := &Token{}
	if tok.IsValid() {
		t.Fatal("empty token should not be valid")
	}
}

func TestIsValidExpired(t *testing.T) {
	tok := &Token{
		AccessToken:           "abc",
		AccessTokenExpiration: time.Now().Add(-time.Hour).Format(time.RFC3339),
	}
	if tok.IsValid() {
		t.Fatal("expired token should not be valid")
	}
}

func TestIsValidFuture(t *testing.T) {
	tok := &Token{
		AccessToken:           "abc",
		AccessTokenExpiration: time.Now().Add(time.Hour).Format(time.RFC3339),
	}
	if !tok.IsValid() {
		t.Fatal("token expiring in the future should be valid")
	}
}

func TestIsValidPythonISOFormat(t *testing.T) {
	// Mimics Python's datetime.now().isoformat(), e.g. "2099-01-02T03:04:05.123456"
	future := time.Now().Add(time.Hour).Format("2006-01-02T15:04:05.000000")
	tok := &Token{AccessToken: "abc", AccessTokenExpiration: future}
	if !tok.IsValid() {
		t.Fatalf("token with python-style expiration %q should be valid", future)
	}
}

func TestApplyResponseSetsFields(t *testing.T) {
	tok := &Token{RefreshToken: "old-refresh"}
	tok.ApplyResponse("new-access", 3600, "", 0)
	if tok.AccessToken != "new-access" {
		t.Errorf("AccessToken = %q, want %q", tok.AccessToken, "new-access")
	}
	if tok.RefreshToken != "old-refresh" {
		t.Errorf("RefreshToken should be preserved when response omits it, got %q", tok.RefreshToken)
	}
	exp, err := ParseTime(tok.AccessTokenExpiration)
	if err != nil {
		t.Fatalf("expiration did not parse: %v", err)
	}
	if time.Until(exp) < 59*time.Minute || time.Until(exp) > 61*time.Minute {
		t.Errorf("expiration %v not ~1h from now", exp)
	}

	tok.ApplyResponse("newer-access", 60, "new-refresh", 0)
	if tok.RefreshToken != "new-refresh" {
		t.Errorf("RefreshToken = %q, want %q", tok.RefreshToken, "new-refresh")
	}
}

func TestApplyResponseRefreshExpiration(t *testing.T) {
	t.Run("new refresh token with reported expiry sets it", func(t *testing.T) {
		tok := &Token{}
		tok.ApplyResponse("a", 3600, "r1", 7776000)
		if tok.RefreshToken != "r1" {
			t.Fatalf("RefreshToken = %q, want %q", tok.RefreshToken, "r1")
		}
		exp, err := ParseTime(tok.RefreshTokenExpiration)
		if err != nil {
			t.Fatalf("RefreshTokenExpiration did not parse: %v", err)
		}
		if d := time.Until(exp); d < 89*24*time.Hour || d > 91*24*time.Hour {
			t.Errorf("refresh expiration %v not ~90d from now", exp)
		}
	})

	t.Run("new refresh token without reported expiry clears any previous one", func(t *testing.T) {
		tok := &Token{RefreshToken: "r1", RefreshTokenExpiration: time.Now().Add(time.Hour).Format(time.RFC3339)}
		tok.ApplyResponse("a", 3600, "r2", 0)
		if tok.RefreshToken != "r2" {
			t.Fatalf("RefreshToken = %q, want %q", tok.RefreshToken, "r2")
		}
		if tok.RefreshTokenExpiration != "" {
			t.Errorf("RefreshTokenExpiration = %q, want empty (unknown) for the new token", tok.RefreshTokenExpiration)
		}
	})

	t.Run("same refresh token kept, new expiry reported, gets applied", func(t *testing.T) {
		tok := &Token{RefreshToken: "r1"}
		tok.ApplyResponse("a", 3600, "r1", 3600)
		exp, err := ParseTime(tok.RefreshTokenExpiration)
		if err != nil {
			t.Fatalf("RefreshTokenExpiration did not parse: %v", err)
		}
		if time.Until(exp) <= 0 {
			t.Errorf("expected a future refresh expiration, got %v", exp)
		}
	})

	t.Run("no refresh token in response, no expiry reported, existing state untouched", func(t *testing.T) {
		wantExp := time.Now().Add(2 * time.Hour).Format(time.RFC3339)
		tok := &Token{RefreshToken: "r1", RefreshTokenExpiration: wantExp}
		tok.ApplyResponse("a", 3600, "", 0)
		if tok.RefreshToken != "r1" {
			t.Errorf("RefreshToken = %q, want %q", tok.RefreshToken, "r1")
		}
		if tok.RefreshTokenExpiration != wantExp {
			t.Errorf("RefreshTokenExpiration = %q, want %q (untouched)", tok.RefreshTokenExpiration, wantExp)
		}
	})
}

func TestParseTimeInvalid(t *testing.T) {
	if _, err := ParseTime("not-a-time"); err == nil {
		t.Fatal("expected error for invalid timestamp")
	}
}

func TestStoreLoadRoundTrip(t *testing.T) {
	keyring.MockInit()

	if tok, err := Load("nobody@example.com"); err != nil || tok != nil {
		t.Fatalf("Load for unknown account = (%v, %v), want (nil, nil)", tok, err)
	}

	want := &Token{
		AccessToken:           "access-123",
		AccessTokenExpiration: time.Now().Add(time.Hour).Format(time.RFC3339),
		RefreshToken:          "refresh-456",
	}
	if err := Store("someone@example.com", want); err != nil {
		t.Fatalf("Store returned error: %v", err)
	}

	got, err := Load("someone@example.com")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if got == nil || *got != *want {
		t.Errorf("Load() = %+v, want %+v", got, want)
	}
}

// TestStoreLoadLargeTokenIsChunked covers corporate/AAD access tokens large
// enough (lots of group claims, etc.) to exceed a single keyring entry's
// practical size limit on some backends (e.g. Windows Credential Manager's
// ~2560 byte password cap, or macOS Keychain's ~3000 byte combined limit) -
// surfaced as go-keyring's "data passed to Set was too big". Store must
// transparently split such tokens across multiple keyring entries, and Load
// must transparently reassemble them.
func TestStoreLoadLargeTokenIsChunked(t *testing.T) {
	keyring.MockInit()

	// Comfortably larger than chunkSize so this exercises multiple chunks.
	bigAccessToken := "jwt." + strings.Repeat("A", chunkSize*3) + ".sig"
	want := &Token{
		AccessToken:           bigAccessToken,
		AccessTokenExpiration: time.Now().Add(time.Hour).Format(time.RFC3339),
		RefreshToken:          "refresh-456",
	}
	if err := Store("big@example.com", want); err != nil {
		t.Fatalf("Store returned error: %v", err)
	}

	// The main entry should now hold the chunk marker, not raw token JSON.
	raw, err := keyring.Get(Service, "big@example.com")
	if err != nil {
		t.Fatalf("keyring.Get(main entry) returned error: %v", err)
	}
	if !strings.HasPrefix(raw, chunkedMarkerPrefix) {
		t.Fatalf("main entry = %q, want it to start with %q", raw, chunkedMarkerPrefix)
	}

	got, err := Load("big@example.com")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if got == nil || *got != *want {
		t.Errorf("Load() did not round-trip the large token correctly")
	}
}

// TestStoreShrinkingTokenCleansUpOldChunks covers going from a large
// (chunked) token to a small one for the same account - e.g. a refresh that
// happens to come back with a shorter access token. Leftover chunk entries
// from the previous, larger write must be removed, not left dangling in the
// keyring forever.
func TestStoreShrinkingTokenCleansUpOldChunks(t *testing.T) {
	keyring.MockInit()

	big := &Token{
		AccessToken:           "jwt." + strings.Repeat("A", chunkSize*3) + ".sig",
		AccessTokenExpiration: time.Now().Add(time.Hour).Format(time.RFC3339),
	}
	if err := Store("shrinking@example.com", big); err != nil {
		t.Fatalf("Store(big) returned error: %v", err)
	}

	// Confirm chunk 2 actually exists before shrinking.
	if _, err := keyring.Get(Service, chunkKey("shrinking@example.com", 2)); err != nil {
		t.Fatalf("expected chunk 2 to exist after storing the large token: %v", err)
	}

	small := &Token{
		AccessToken:           "short",
		AccessTokenExpiration: time.Now().Add(time.Hour).Format(time.RFC3339),
	}
	if err := Store("shrinking@example.com", small); err != nil {
		t.Fatalf("Store(small) returned error: %v", err)
	}

	if _, err := keyring.Get(Service, chunkKey("shrinking@example.com", 2)); !errorsIsNotFound(err) {
		t.Errorf("expected chunk 2 to be cleaned up after shrinking, got err=%v", err)
	}

	got, err := Load("shrinking@example.com")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if got == nil || *got != *small {
		t.Errorf("Load() = %+v, want %+v", got, small)
	}
}

func errorsIsNotFound(err error) bool {
	return errors.Is(err, keyring.ErrNotFound)
}

// TestLoadSelfHealsFromMissingChunk covers a chunked marker entry that
// references a chunk which isn't actually retrievable - e.g. an interrupted
// write, or (as happened once during development) a chunk-naming scheme
// change that left an old marker pointing at keys the current code no
// longer looks for. The old token is unrecoverable either way; Load must
// treat that the same as "never authorized" (nil, nil) rather than
// returning a hard error forever, so a plain "omt authorize" can recover.
func TestLoadSelfHealsFromMissingChunk(t *testing.T) {
	keyring.MockInit()

	// Write a marker claiming 2 chunks, but only actually store the first
	// one - simulating a partially-written or renamed-scheme entry.
	if err := keyring.Set(Service, "broken@example.com", chunkedMarkerPrefix+"2"); err != nil {
		t.Fatalf("keyring.Set(marker) returned error: %v", err)
	}
	if err := keyring.Set(Service, chunkKey("broken@example.com", 0), `{"access_token":`); err != nil {
		t.Fatalf("keyring.Set(chunk 0) returned error: %v", err)
	}
	// Chunk 1 is deliberately never written.

	got, err := Load("broken@example.com")
	if err != nil {
		t.Fatalf("Load returned error: %v, want nil (self-heal to \"not authorized\")", err)
	}
	if got != nil {
		t.Errorf("Load() = %+v, want nil", got)
	}
}
