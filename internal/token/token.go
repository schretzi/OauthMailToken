// Package token manages the OAuth2 access/refresh tokens persisted for each
// account in the OS keyring.
package token

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/zalando/go-keyring"
)

// Service is the keyring service name under which tokens are stored,
// matching the Python implementation's keyringSystem constant.
const Service = "OauthMailToken"

// chunkSize is the maximum size, in bytes, of a single keyring entry's
// value written by this package. Some backends impose fairly small limits
// on top of the OS's own item-size limit - notably Windows Credential
// Manager (password data capped at 2560 bytes) and macOS Keychain (roughly
// 3000 bytes across service+account+password combined). Corporate/AAD
// access tokens in particular can carry enough claims (group memberships
// etc.) to blow past those limits, which surfaces as go-keyring's
// ErrSetDataTooBig ("data passed to Set was too big"). To stay within the
// OS keyring (rather than falling back to a plaintext file) tokens that
// don't fit in one entry are split across several, see Store/Load below.
const chunkSize = 1800

// chunkedMarkerPrefix is stored under the account's main keyring entry when
// its data was split into chunks; the suffix is the chunk count. A plain,
// unprefixed value at that entry (the common case - most tokens are small
// enough for a single entry, and this is also what every token written
// before chunking support existed looks like) is read as-is.
const chunkedMarkerPrefix = "##omt-chunked##"

func chunkKey(account string, i int) string {
	// No NUL bytes or other characters that could confuse a keyring backend
	// that shells out to an external tool (e.g. macOS's /usr/bin/security,
	// which rejects NUL-containing arguments with "invalid argument" at the
	// exec level) - a plain, human-readable suffix is safest.
	return fmt.Sprintf("%s##chunk%d", account, i)
}

// Token represents the OAuth2 tokens persisted for one account.
type Token struct {
	AccessToken           string `json:"access_token"`
	AccessTokenExpiration string `json:"access_token_expiration"`
	RefreshToken          string `json:"refresh_token,omitempty"`
	// RefreshTokenExpiration is the refresh token's own expiration, only set
	// when the provider actually reported one (see
	// oauth.TokenResponse.RefreshExpiresIn) - most providers don't, so an
	// empty value here means "unknown/not reported", not "never expires".
	RefreshTokenExpiration string `json:"refresh_token_expiration,omitempty"`
}

// IsValid reports whether the stored access token exists and has not expired
// yet, mirroring the Python implementation's access_token_valid().
func (t *Token) IsValid() bool {
	if t == nil || t.AccessToken == "" || t.AccessTokenExpiration == "" {
		return false
	}
	exp, err := ParseTime(t.AccessTokenExpiration)
	if err != nil {
		return false
	}
	return time.Now().Before(exp)
}

// ApplyResponse updates the access token and its expiration, mirroring the
// Python implementation's update_tokens(). refreshToken and
// refreshExpiresInSeconds come from the same token endpoint response and are
// handled as a pair:
//
//   - If the response issued a new refresh token (refreshToken != ""), it
//     replaces the stored one. Its expiration is set only if the response
//     also reported one (refreshExpiresInSeconds > 0); otherwise it's
//     cleared, since a stale expiration from a *different* refresh token
//     would be actively misleading.
//   - If the response didn't issue a new refresh token (the common case:
//     providers often only send one on the very first authorization), the
//     existing refresh token is left untouched, but its expiration is still
//     updated if the response reported one for it.
func (t *Token) ApplyResponse(accessToken string, expiresInSeconds int, refreshToken string, refreshExpiresInSeconds int) {
	t.AccessToken = accessToken
	t.AccessTokenExpiration = time.Now().Add(time.Duration(expiresInSeconds) * time.Second).Format(time.RFC3339)

	if refreshToken != "" && refreshToken != t.RefreshToken {
		t.RefreshToken = refreshToken
		t.RefreshTokenExpiration = ""
	}
	if refreshExpiresInSeconds > 0 {
		t.RefreshTokenExpiration = time.Now().Add(time.Duration(refreshExpiresInSeconds) * time.Second).Format(time.RFC3339)
	}
}

// timeLayouts are the timestamp layouts accepted when parsing a stored
// expiration: our own RFC3339 output, plus the naive datetime.isoformat()
// layouts Python's datetime.now().isoformat() can produce, so tokens written
// by the legacy Python implementation keep working after switching to Go.
var timeLayouts = []string{
	time.RFC3339,
	time.RFC3339Nano,
	"2006-01-02T15:04:05.000000",
	"2006-01-02T15:04:05",
}

// ParseTime parses a token expiration timestamp, accepting both the RFC3339
// format written by this program and the naive datetime.isoformat() layouts
// written by the legacy Python implementation.
func ParseTime(s string) (time.Time, error) {
	var lastErr error
	for _, layout := range timeLayouts {
		if ts, err := time.Parse(layout, s); err == nil {
			return ts, nil
		} else {
			lastErr = err
		}
	}
	return time.Time{}, lastErr
}

// Store persists tokens for account via the OS keyring. If the serialized
// token is too large for a single keyring entry (see chunkSize), it's
// transparently split across multiple entries instead of failing or falling
// back to a plaintext file - see chunkedMarkerPrefix.
func Store(account string, t *Token) error {
	data, err := json.Marshal(t)
	if err != nil {
		return err
	}

	oldChunks, _ := chunkCountOf(account)

	if len(data) <= chunkSize {
		if err := keyring.Set(Service, account, string(data)); err != nil {
			return err
		}
		deleteChunks(account, 0, oldChunks)
		return nil
	}

	n := (len(data) + chunkSize - 1) / chunkSize
	for i := 0; i < n; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(data) {
			end = len(data)
		}
		if err := keyring.Set(Service, chunkKey(account, i), string(data[start:end])); err != nil {
			return fmt.Errorf("storing chunk %d/%d: %w", i+1, n, err)
		}
	}
	if err := keyring.Set(Service, account, chunkedMarkerPrefix+strconv.Itoa(n)); err != nil {
		return err
	}
	deleteChunks(account, n, oldChunks)
	return nil
}

// chunkCountOf returns how many chunk entries account's current keyring
// entry says it has (0 if it isn't chunked, or nothing is stored yet).
func chunkCountOf(account string) (int, error) {
	data, err := keyring.Get(Service, account)
	if err != nil {
		return 0, err
	}
	if !strings.HasPrefix(data, chunkedMarkerPrefix) {
		return 0, nil
	}
	n, err := strconv.Atoi(strings.TrimPrefix(data, chunkedMarkerPrefix))
	if err != nil {
		return 0, err
	}
	return n, nil
}

// deleteChunks removes chunk entries [from, to) for account, ignoring
// not-found errors - used to clean up leftover chunks from a previous,
// larger write once a smaller one has replaced it.
func deleteChunks(account string, from, to int) {
	for i := from; i < to; i++ {
		_ = keyring.Delete(Service, chunkKey(account, i))
	}
}

// Load reads tokens for account from the OS keyring. It returns (nil, nil)
// if no token has been stored yet, mirroring the Python implementation's
// readToken() behaviour of returning None.
func Load(account string) (*Token, error) {
	data, err := keyring.Get(Service, account)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if data == "" || data == "null" {
		return nil, nil
	}

	if strings.HasPrefix(data, chunkedMarkerPrefix) {
		n, err := strconv.Atoi(strings.TrimPrefix(data, chunkedMarkerPrefix))
		if err != nil {
			return nil, fmt.Errorf("parsing chunk count: %w", err)
		}
		var sb strings.Builder
		for i := 0; i < n; i++ {
			part, err := keyring.Get(Service, chunkKey(account, i))
			if err != nil {
				if errors.Is(err, keyring.ErrNotFound) {
					// The marker entry references a chunk that isn't there.
					// This can happen after an interrupted/partial write, or
					// after a chunk-naming scheme change (as happened once
					// during development of this feature) - the previously
					// stored token is unrecoverable either way. Rather than
					// permanently erroring out of every command for this
					// account, treat it the same as "never authorized" so
					// "omt authorize" can cleanly overwrite it.
					fmt.Fprintf(os.Stderr, "NOTICE: stored token for %q is incomplete (missing chunk %d/%d) - treating as not authorized; run \"omt authorize %s\" to fix.\n", account, i+1, n, account)
					return nil, nil
				}
				return nil, fmt.Errorf("reading chunk %d/%d: %w", i+1, n, err)
			}
			sb.WriteString(part)
		}
		data = sb.String()
	}

	var t Token
	if err := json.Unmarshal([]byte(data), &t); err != nil {
		return nil, err
	}
	return &t, nil
}
