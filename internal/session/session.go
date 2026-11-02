// Package session implements HMAC-signed session tokens.
//
// Tokens are a single opaque string:
//
//	base64url(payloadJSON) + "." + base64url(HMAC-SHA256(payloadJSON, key))
//
// The payload carries the authenticated email and expiry time; no server-side
// storage is required, and a leaked/rotated cookie secret immediately
// invalidates every outstanding session.
package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrInvalid is returned from Verify when the token is malformed, tampered
// with, or past its expiry.
var ErrInvalid = errors.New("invalid or expired session token")

// Payload is the JSON body embedded in each token.
type Payload struct {
	// Email is the authenticated user's primary email address.
	Email string `json:"email"`

	// Name is a display name (optional, used only for logging/headers).
	Name string `json:"name,omitempty"`

	// IssuedAt is Unix seconds when the token was minted.
	IssuedAt int64 `json:"iat"`

	// ExpiresAt is Unix seconds when the token stops being valid.
	ExpiresAt int64 `json:"exp"`
}

// Issue creates a new signed token for the given user, valid for ttl.
func Issue(key []byte, email, name string, ttl time.Duration) (string, error) {
	now := time.Now().UTC()
	p := Payload{
		Email:     email,
		Name:      name,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
	}
	return encode(key, p)
}

// Verify parses and validates a token against a single key. See VerifyAny.
func Verify(key []byte, token string) (*Payload, error) {
	return VerifyAny([][]byte{key}, token)
}

// VerifyAny parses and validates a token against a set of keys: the current
// key first, then any previous ones still accepted during a secret rotation.
// It returns the embedded payload on success; the error is ErrInvalid for any
// parse/signature/expiry failure so callers can treat it uniformly.
func VerifyAny(keys [][]byte, token string) (*Payload, error) {
	payloadB64, sigB64, ok := splitOnce(token, '.')
	if !ok {
		return nil, ErrInvalid
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, ErrInvalid
	}
	got, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, ErrInvalid
	}
	if !macOK(keys, payloadJSON, got) {
		return nil, ErrInvalid
	}
	var p Payload
	if err := json.Unmarshal(payloadJSON, &p); err != nil {
		return nil, ErrInvalid
	}
	if time.Now().UTC().Unix() >= p.ExpiresAt {
		return nil, ErrInvalid
	}
	if p.Email == "" {
		return nil, ErrInvalid
	}
	return &p, nil
}

// SignState mints a short-lived, signed token carrying a string (the post-login
// redirect for OAuth state, or the admin's email for a CSRF token). It uses the
// same HMAC key as sessions; the value is never a long-lived credential.
func SignState(key []byte, redirect string, ttl time.Duration) (string, error) {
	return SignLoginState(key, redirect, "", ttl)
}

// SignLoginState is SignState plus a nonce. The caller also stores the nonce in
// a cookie on the browser that started the login and checks that the two match
// when Yandex redirects back, so a state minted for one browser cannot be used
// to complete a login in another (login CSRF).
func SignLoginState(key []byte, redirect, nonce string, ttl time.Duration) (string, error) {
	now := time.Now().UTC()
	p := statePayload{
		Redirect:  redirect,
		Nonce:     nonce,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
	}
	b, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("marshal state: %w", err)
	}
	sig := mac(key, b)
	return base64.RawURLEncoding.EncodeToString(b) + "." +
		base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyState returns the string encoded in a previously-minted state, or
// ErrInvalid if it's forged or expired.
func VerifyState(key []byte, state string) (string, error) {
	return VerifyStateAny([][]byte{key}, state)
}

// VerifyStateAny is VerifyState against a set of keys (see VerifyAny).
func VerifyStateAny(keys [][]byte, state string) (string, error) {
	redirect, _, err := VerifyLoginState(keys, state)
	return redirect, err
}

// VerifyLoginState returns the redirect and the nonce encoded in a state.
func VerifyLoginState(keys [][]byte, state string) (redirect, nonce string, err error) {
	payloadB64, sigB64, ok := splitOnce(state, '.')
	if !ok {
		return "", "", ErrInvalid
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return "", "", ErrInvalid
	}
	got, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return "", "", ErrInvalid
	}
	if !macOK(keys, payloadJSON, got) {
		return "", "", ErrInvalid
	}
	var p statePayload
	if err := json.Unmarshal(payloadJSON, &p); err != nil {
		return "", "", ErrInvalid
	}
	if time.Now().UTC().Unix() >= p.ExpiresAt {
		return "", "", ErrInvalid
	}
	return p.Redirect, p.Nonce, nil
}

type statePayload struct {
	Redirect  string `json:"rd"`
	Nonce     string `json:"n,omitempty"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

func encode(key []byte, p Payload) (string, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}
	sig := mac(key, b)
	return base64.RawURLEncoding.EncodeToString(b) + "." +
		base64.RawURLEncoding.EncodeToString(sig), nil
}

// macOK reports whether got is a valid signature of data under any of the keys.
// It always checks every key, so the time taken does not reveal which one matched.
func macOK(keys [][]byte, data, got []byte) bool {
	ok := false
	for _, k := range keys {
		if hmac.Equal(got, mac(k, data)) {
			ok = true
		}
	}
	return ok
}

func mac(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// splitOnce splits s at the first occurrence of sep; returns (left, right, true)
// if sep was found, (s, "", false) otherwise. Avoids strings.SplitN overhead.
func splitOnce(s string, sep byte) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}
