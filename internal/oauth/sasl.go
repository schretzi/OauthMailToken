// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 schretzi

package oauth

import "fmt"

// BuildSASLString builds the SASL initial-response string for the given
// method, to be handed to an IMAP/POP/SMTP server's OAuth2 login command
// (e.g. by mutt). Supported methods are "OAUTHBEARER" (RFC 7628) and
// "XOAUTH2" (used by Microsoft/Google's older SASL mechanism).
func BuildSASLString(method, user, host string, port int, bearerToken string) (string, error) {
	switch method {
	case "OAUTHBEARER":
		return fmt.Sprintf("n,a=%s,\x01host=%s\x01port=%d\x01auth=Bearer %s\x01\x01", user, host, port, bearerToken), nil
	case "XOAUTH2":
		return fmt.Sprintf("user=%s\x01auth=Bearer %s\x01\x01", user, bearerToken), nil
	default:
		return "", fmt.Errorf("unknown SASL method %q", method)
	}
}
