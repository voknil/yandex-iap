// Package yandex wraps the small slice of Yandex OAuth we actually use.
//
// Yandex documentation: https://yandex.ru/dev/id/doc/en/.
// The flow deliberately does not use Yandex ID-tokens (they aren't issued) —
// instead, after exchanging the authorization code we call login.yandex.ru/info
// with the access token to get the user's primary email.
package yandex

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	authEndpoint     = "https://oauth.yandex.ru/authorize"
	tokenEndpoint    = "https://oauth.yandex.ru/token"
	userInfoEndpoint = "https://login.yandex.ru/info?format=json"
)

// Client performs OAuth calls against Yandex.
type Client struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	HTTP         *http.Client
}

// New returns a Client with a 10-second HTTP timeout.
func New(clientID, clientSecret, redirectURI string) *Client {
	return &Client{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  redirectURI,
		HTTP:         &http.Client{Timeout: 10 * time.Second},
	}
}

// AuthorizeURL builds the full redirect URL to send the user to start login.
func (c *Client) AuthorizeURL(state, scopes string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", c.ClientID)
	q.Set("redirect_uri", c.RedirectURI)
	q.Set("state", state)
	if scopes != "" {
		q.Set("scope", scopes)
	}
	// force_confirm=yes не требуется — Yandex сам кеширует согласие на клиенте.
	return authEndpoint + "?" + q.Encode()
}

// TokenResponse is the subset of the token endpoint we care about.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// ExchangeCode trades an authorization code for an access token.
func (c *Client) ExchangeCode(ctx context.Context, code string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", c.ClientID)
	form.Set("client_secret", c.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token endpoint: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d: %s",
			resp.StatusCode, trim(body))
	}
	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	if tr.AccessToken == "" {
		return nil, errors.New("token endpoint returned empty access_token")
	}
	return &tr, nil
}

// UserInfo captures the fields we read from login.yandex.ru/info.
// Yandex returns more fields (birthday, sex, login, avatar id, …); we only
// deserialize what the proxy needs to enforce the whitelist and populate
// identity headers.
type UserInfo struct {
	ID           string   `json:"id"`
	Login        string   `json:"login"`
	DisplayName  string   `json:"display_name"`
	RealName     string   `json:"real_name"`
	FirstName    string   `json:"first_name"`
	LastName     string   `json:"last_name"`
	DefaultEmail string   `json:"default_email"`
	Emails       []string `json:"emails"`
}

// PrimaryEmail picks the best email to treat as the user's identity.
// Yandex accounts always have default_email populated; fall back to the
// first entry of emails[] defensively.
func (u *UserInfo) PrimaryEmail() string {
	if u.DefaultEmail != "" {
		return strings.ToLower(strings.TrimSpace(u.DefaultEmail))
	}
	if len(u.Emails) > 0 {
		return strings.ToLower(strings.TrimSpace(u.Emails[0]))
	}
	return ""
}

// Name returns a human-friendly name, preferring real_name over display_name.
// Never returns an empty string if any name field is set.
func (u *UserInfo) Name() string {
	for _, v := range []string{u.RealName, u.DisplayName, u.Login} {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// FetchUserInfo calls login.yandex.ru/info with the access token.
// The token is sent as "OAuth <token>" per Yandex convention (not "Bearer").
func (c *Client) FetchUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "OAuth "+accessToken)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo endpoint: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read userinfo response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo endpoint returned %d: %s",
			resp.StatusCode, trim(body))
	}
	var u UserInfo
	if err := json.Unmarshal(body, &u); err != nil {
		return nil, fmt.Errorf("decode userinfo: %w", err)
	}
	if u.PrimaryEmail() == "" {
		return nil, errors.New("userinfo response has no usable email")
	}
	return &u, nil
}

func trim(b []byte) string {
	const max = 512
	if len(b) > max {
		return string(b[:max]) + "…"
	}
	return string(b)
}
