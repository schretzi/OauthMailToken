package oauth

import (
	"net/http"
	"net/url"

	"github.com/schretzi/oauthmailtoken/internal/config"
)

// ExchangeRefreshToken exchanges a stored refresh token for a new access
// token. Note: unlike the authcode/devicecode flows, this intentionally does
// not send the provider's "tenant" parameter, matching the original Python
// implementation's refresh request.
func ExchangeRefreshToken(client *http.Client, provider config.ProviderConfig, refreshToken string) (TokenResponse, error) {
	params := url.Values{}
	params.Set("client_id", provider.ClientID)
	if provider.ClientSecret != "" {
		// See the comment in devicecode.go's PollDeviceToken: public clients
		// (no secret configured) must omit this parameter entirely.
		params.Set("client_secret", provider.ClientSecret)
	}
	params.Set("refresh_token", refreshToken)
	params.Set("grant_type", "refresh_token")

	tr, _, err := postForm(client, provider.TokenEndpoint, params)
	return tr, err
}
