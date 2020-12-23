package indieauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"hawx.me/code/assert"
)

func urlParse(s string) *url.URL {
	u, _ := url.Parse(s)
	return u
}

func TestAuthorizationRedirect(t *testing.T) {
	assert := assert.New(t)

	authEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer authEndpoint.Close()

	session := &AuthorizationConfig{
		ClientID:    urlParse("https://webapp.example.com/"),
		RedirectURI: urlParse("https://webapp.example.com/callback"),
		Scopes:      []string{"create", "update", "delete"},
	}

	endpoints := Endpoints{
		Authorization: urlParse(authEndpoint.URL),
	}

	redirectURL := session.RedirectURL(endpoints, "https://me.example.com", "1234")

	expectedRedirect := authEndpoint.URL +
		"?client_id=https%3A%2F%2Fwebapp.example.com%2F" +
		"&me=https%3A%2F%2Fme.example.com" +
		"&redirect_uri=https%3A%2F%2Fwebapp.example.com%2Fcallback" +
		"&response_type=code" +
		"&scope=create+update+delete" +
		"&state=1234"

	assert.Equal(expectedRedirect, redirectURL)
}

func TestAuthorizationVerify(t *testing.T) {
	assert := assert.New(t)

	var meEndpoint *httptest.Server

	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" ||
			r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" ||
			r.FormValue("grant_type") != "authorization_code" ||
			r.FormValue("code") != "abcde" ||
			r.FormValue("client_id") != "http://localhost" ||
			r.FormValue("redirect_uri") != "http://localhost/callback" ||
			r.FormValue("me") != "http://me.localhost" {
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
  "access_token": "tokentoken",
  "token_type": "Bearer",
  "scope": "create update delete",
  "me": "` + meEndpoint.URL + `"
}`))
	}))
	defer tokenEndpoint.Close()

	meEndpoint = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<link rel="authorization_endpoint" href="http://example.com/auth"/>`))
	}))
	defer meEndpoint.Close()

	session := &AuthorizationConfig{
		ClientID:    urlParse("http://localhost"),
		RedirectURI: urlParse("http://localhost/callback"),
	}

	endpoints := Endpoints{
		Authorization: urlParse("http://example.com/auth"),
		Token:         urlParse(tokenEndpoint.URL),
	}

	token, err := session.Exchange(endpoints, "abcde", "http://me.localhost")

	assert.Nil(err)
	assert.Equal("tokentoken", token.AccessToken)
	assert.Equal("Bearer", token.TokenType)
	assert.Len(token.Scopes, 3)
	assert.True(token.HasScope("create"))
	assert.True(token.HasScope("update"))
	assert.True(token.HasScope("delete"))
	assert.Equal(meEndpoint.URL, token.Me)
}

func TestAuthorizationVerifyCannotBeClaimed(t *testing.T) {
	assert := assert.New(t)

	var meEndpoint *httptest.Server

	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" ||
			r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" ||
			r.FormValue("grant_type") != "authorization_code" ||
			r.FormValue("code") != "abcde" ||
			r.FormValue("client_id") != "http://localhost" ||
			r.FormValue("redirect_uri") != "http://localhost/callback" ||
			r.FormValue("me") != "http://me.localhost" {
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
  "access_token": "tokentoken",
  "token_type": "Bearer",
  "scope": "create update delete",
  "me": "` + meEndpoint.URL + `"
}`))
	}))
	defer tokenEndpoint.Close()

	meEndpoint = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<link rel="authorization_endpoint" href="https://legit.example.com"/>`))
	}))
	defer meEndpoint.Close()

	session := &AuthorizationConfig{
		ClientID:    urlParse("http://localhost"),
		RedirectURI: urlParse("http://localhost/callback"),
	}

	endpoints := Endpoints{
		Authorization: urlParse("http://example.com/auth"),
		Token:         urlParse(tokenEndpoint.URL),
	}

	token, err := session.Exchange(endpoints, "abcde", "http://me.localhost")

	assert.Equal(errCannotClaim, err)
	assert.Equal(Token{}, token)
}
