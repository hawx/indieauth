package indieauth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"hawx.me/code/assert"
)

type testTokenEndpoint struct {
	t     *testing.T
	meURL string
}

func (e *testTokenEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	assert := assert.Wrap(e.t)

	ok := assert(r.Method).Equal("POST") ||
		assert(r.Header.Get("Content-Type")).Equal("application/x-www-form-urlencoded") ||
		assert(r.FormValue("grant_type")).Equal("authorization_code") ||
		assert(r.FormValue("code")).Equal("abcde") ||
		assert(r.FormValue("client_id")).Equal("http://localhost") ||
		assert(r.FormValue("redirect_uri")).Equal("http://localhost/callback") ||
		assert(r.FormValue("code_verifier")).Equal("verifier")

	if ok {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token": "tokentoken", "token_type": "Bearer", "scope": "create update delete", "me": "%s"}`, e.meURL)
	} else {
		http.Error(w, "", http.StatusBadRequest)
	}
}

type testAuthEndpoint struct {
	t     *testing.T
	meURL string
}

func (e *testAuthEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	assert := assert.Wrap(e.t)

	ok := assert(r.Method).Equal("POST") ||
		assert(r.Header.Get("Content-Type")).Equal("application/x-www-form-urlencoded") ||
		assert(r.FormValue("grant_type")).Equal("authorization_code") ||
		assert(r.FormValue("code")).Equal("abcde") ||
		assert(r.FormValue("client_id")).Equal("http://localhost") ||
		assert(r.FormValue("redirect_uri")).Equal("http://localhost/callback") ||
		assert(r.FormValue("code_verifier")).Equal("verifier")

	if ok {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"me": "%s", "profile": {"name": "John Doe"}}`, e.meURL)
	} else {
		http.Error(w, "", http.StatusBadRequest)
	}
}

type testMeEndpoint struct {
	auth  string
	token string
}

func (e *testMeEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<link rel="authorization_endpoint" href="%s"/>`, e.auth)
}

func urlParse(s string) *url.URL {
	u, _ := url.Parse(s)
	return u
}

func TestAuthCodeURL(t *testing.T) {
	assert := assert.Wrap(t)

	authEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer authEndpoint.Close()

	session := &Config{
		ClientID:    "https://webapp.example.com/",
		RedirectURL: "https://webapp.example.com/callback",
		Scopes:      []string{"create", "update", "delete"},
	}

	endpoints := Endpoints{
		Authorization: urlParse(authEndpoint.URL),
	}

	redirectURL := session.AuthCodeURL(endpoints, "1234", "challenge", "https://me.example.com")

	expectedRedirect := authEndpoint.URL +
		"?client_id=https%3A%2F%2Fwebapp.example.com%2F" +
		"&code_challenge=challenge" +
		"&code_challenge_method=S256" +
		"&me=https%3A%2F%2Fme.example.com" +
		"&redirect_uri=https%3A%2F%2Fwebapp.example.com%2Fcallback" +
		"&response_type=code" +
		"&scope=create+update+delete" +
		"&state=1234"

	assert(redirectURL).Equal(expectedRedirect)
}

func TestExchange(t *testing.T) {
	assert := assert.Wrap(t)

	te := &testTokenEndpoint{t: t}

	ts := httptest.NewServer(te)
	defer ts.Close()

	ms := httptest.NewServer(&testMeEndpoint{auth: "http://example.com/auth"})
	defer ms.Close()

	te.meURL = ms.URL

	session := &Config{
		ClientID:    "http://localhost",
		RedirectURL: "http://localhost/callback",
		Scopes:      []string{"create"},
	}

	endpoints := Endpoints{
		Authorization: urlParse("http://example.com/auth"),
		Token:         urlParse(ts.URL),
	}

	token, err := session.Exchange(endpoints, "abcde", "verifier")
	assert(err).Must.Nil()

	assert(token.AccessToken).Equal("tokentoken")
	assert(token.TokenType).Equal("Bearer")
	assert(token.Scopes).Len(3)
	assert(token.HasScope("create")).True()
	assert(token.HasScope("update")).True()
	assert(token.HasScope("delete")).True()
	assert(token.Me).Equal(ms.URL)
}

func TestExchangeOnlyMe(t *testing.T) {
	assert := assert.Wrap(t)

	te := &testAuthEndpoint{t: t}

	ts := httptest.NewServer(te)
	defer ts.Close()

	ms := httptest.NewServer(&testMeEndpoint{auth: ts.URL})
	defer ms.Close()

	te.meURL = ms.URL

	session := &Config{
		ClientID:    "http://localhost",
		RedirectURL: "http://localhost/callback",
		Scopes:      []string{"profile"},
	}

	endpoints := Endpoints{
		Authorization: urlParse(ts.URL),
	}

	token, err := session.Exchange(endpoints, "abcde", "verifier")
	assert(err).Must.Nil()

	assert(token.AccessToken).Equal("")
	assert(token.TokenType).Equal("")
	assert(token.Scopes).Len(0)
	assert(token.Me).Equal(ms.URL)
	assert(token.Profile).Equal(map[string]interface{}{
		"name": "John Doe",
	})
}

func TestExchangeCannotBeClaimed(t *testing.T) {
	assert := assert.Wrap(t)

	te := &testTokenEndpoint{t: t}

	ts := httptest.NewServer(te)
	defer ts.Close()

	ms := httptest.NewServer(&testMeEndpoint{auth: "https://legit.example.com/auth"})
	defer ms.Close()

	te.meURL = ms.URL

	session := &Config{
		ClientID:    "http://localhost",
		RedirectURL: "http://localhost/callback",
		Scopes:      []string{"create", "update"},
	}

	endpoints := Endpoints{
		Authorization: urlParse("http://example.com/auth"),
		Token:         urlParse(ts.URL),
	}

	token, err := session.Exchange(endpoints, "abcde", "verifier")
	assert(err).Equal(ErrCannotClaim)
	assert(token).Nil()
}
