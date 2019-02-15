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

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/somepath", nil)

	session := AuthorizationSession{
		Me:          urlParse("https://me.example.com"),
		ClientID:    urlParse("https://webapp.example.com/"),
		RedirectURI: urlParse("https://webapp.example.com/callback"),
		State:       "1234",
		Scopes:      []string{"create", "update", "delete"},
		Endpoints: Endpoints{
			Authorization: urlParse(authEndpoint.URL),
		},
	}

	err := session.Redirect(w, r)

	assert.Nil(err)

	resp := w.Result()
	assert.Equal(http.StatusFound, resp.StatusCode)

	expectedRedirect := authEndpoint.URL +
		"?client_id=https%3A%2F%2Fwebapp.example.com%2F" +
		"&me=https%3A%2F%2Fme.example.com" +
		"&redirect_uri=https%3A%2F%2Fwebapp.example.com%2Fcallback" +
		"&response_type=code" +
		"&scope=create+update+delete" +
		"&state=1234"

	assert.Equal(expectedRedirect, resp.Header.Get("Location"))
}

func TestAuthorizationVerify(t *testing.T) {
	assert := assert.New(t)

	authEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
  "me": "https://user.example.net/"
}`))
	}))
	defer authEndpoint.Close()

	session := AuthorizationSession{
		Me:          urlParse("http://me.localhost"),
		ClientID:    urlParse("http://localhost"),
		RedirectURI: urlParse("http://localhost/callback"),
		State:       "1234",
		Endpoints: Endpoints{
			Authorization: urlParse(authEndpoint.URL),
		},
	}

	token, err := session.Verify("abcde")

	assert.Nil(err)
	assert.Equal("tokentoken", token.AccessToken)
	assert.Equal("Bearer", token.TokenType)
	assert.Len(token.Scopes, 3)
	assert.True(token.HasScope("create"))
	assert.True(token.HasScope("update"))
	assert.True(token.HasScope("delete"))
	assert.Equal("https://user.example.net/", token.Me)
}
