package yandex

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func fake(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	c := New("cid", "sec", "https://iap.example.com/auth/callback")
	c.AuthEndpoint = ts.URL + "/authorize"
	c.TokenEndpoint = ts.URL + "/token"
	c.UserInfoEndpoint = ts.URL + "/info"
	return c
}

func TestAuthorizeURL(t *testing.T) {
	c := New("cid", "sec", "https://iap.example.com/auth/callback")
	u, err := url.Parse(c.AuthorizeURL("st", "login:email login:info"))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Host != "oauth.yandex.ru" || u.Path != "/authorize" {
		t.Errorf("unexpected endpoint %s", u)
	}
	for k, want := range map[string]string{
		"response_type": "code", "client_id": "cid", "state": "st",
		"redirect_uri": "https://iap.example.com/auth/callback",
		"scope":        "login:email login:info",
	} {
		if got := q.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

func TestExchangeCode(t *testing.T) {
	c := fake(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Method != http.MethodPost || r.PostForm.Get("code") != "abc" ||
			r.PostForm.Get("grant_type") != "authorization_code" ||
			r.PostForm.Get("client_secret") != "sec" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"AT","token_type":"bearer","expires_in":3600}`))
	})
	tok, err := c.ExchangeCode(context.Background(), "abc")
	if err != nil || tok.AccessToken != "AT" {
		t.Fatalf("got %+v, %v", tok, err)
	}
}

func TestExchangeCodeErrors(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"http error": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		},
		"bad json": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("not json")) },
		"empty token": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"access_token":""}`))
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := fake(t, h).ExchangeCode(context.Background(), "x"); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestFetchUserInfo(t *testing.T) {
	c := fake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "OAuth AT" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"login":"ivan","real_name":"Иван","default_email":" Ivan@Yandex.RU "}`))
	})
	u, err := c.FetchUserInfo(context.Background(), "AT")
	if err != nil {
		t.Fatal(err)
	}
	if u.PrimaryEmail() != "ivan@yandex.ru" || u.Name() != "Иван" {
		t.Errorf("got email %q name %q", u.PrimaryEmail(), u.Name())
	}
	if _, err := c.FetchUserInfo(context.Background(), "wrong"); err == nil {
		t.Error("expected an error for a rejected token")
	}
}

func TestFetchUserInfoNoEmail(t *testing.T) {
	c := fake(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"login":"x"}`)) })
	if _, err := c.FetchUserInfo(context.Background(), "AT"); err == nil {
		t.Fatal("expected an error when no email is present")
	}
}

func TestUserInfoFallbacks(t *testing.T) {
	u := &UserInfo{Emails: []string{" A@B.com "}, DisplayName: "  ", Login: "lg"}
	if u.PrimaryEmail() != "a@b.com" {
		t.Errorf("email fallback: %q", u.PrimaryEmail())
	}
	if u.Name() != "lg" {
		t.Errorf("name fallback: %q", u.Name())
	}
	if strings.TrimSpace((&UserInfo{}).Name()) != "" {
		t.Error("empty user must have an empty name")
	}
}
