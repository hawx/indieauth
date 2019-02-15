package indieauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"hawx.me/code/assert"
)

func TestAuthenticationRedirect(t *testing.T) {
	assert := assert.New(t)

	authEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

	}))
	defer authEndpoint.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/somepath", nil)

	session := AuthenticationSession{
		Me:          urlParse("https://me.example.com"),
		ClientID:    urlParse("https://webapp.example.com/"),
		RedirectURI: urlParse("https://webapp.example.com/callback"),
		State:       "1234",
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
		"&response_type=id" +
		"&state=1234"

	assert.Equal(expectedRedirect, resp.Header.Get("Location"))
}

func TestAuthenticationRedirectWithBadRedirectURI(t *testing.T) {
	assert := assert.New(t)

	authEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

	}))
	defer authEndpoint.Close()

	testCases := []struct {
		Name        string
		ClientID    string
		RedirectURI string
	}{
		{
			Name:        "schemes don't match",
			ClientID:    "https://localhost",
			RedirectURI: "http://localhost/callback",
		},
		{
			Name:        "hosts don't match",
			ClientID:    "https://localhost",
			RedirectURI: "https://not.localhost",
		},
		{
			Name:        "ports don't match",
			ClientID:    "http://localhost:8080",
			RedirectURI: "http://localhost:8081",
		},
	}

	for _, testCase := range testCases {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/somepath", nil)

		session := AuthenticationSession{
			Me:          urlParse("https://me.example.com"),
			ClientID:    urlParse(testCase.ClientID),
			RedirectURI: urlParse(testCase.RedirectURI),
			State:       "1234",
			Endpoints: Endpoints{
				Authorization: urlParse(authEndpoint.URL),
			},
		}

		err := session.Redirect(w, r)

		assert.NotNil(err)

		resp := w.Result()
		assert.Equal(http.StatusBadRequest, resp.StatusCode)
	}
}

func TestAuthenticationRedirectWithBadRedirectURIWhitelistedByHeader(t *testing.T) {
	assert := assert.New(t)

	authEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

	}))
	defer authEndpoint.Close()

	clientEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<https://webapp.example.com/callback>; rel="redirect_uri"`)
	}))
	defer clientEndpoint.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/somepath", nil)

	session := AuthenticationSession{
		Me:          urlParse("https://me.example.com"),
		ClientID:    urlParse(clientEndpoint.URL),
		RedirectURI: urlParse("https://webapp.example.com/callback"),
		State:       "1234",
		Endpoints: Endpoints{
			Authorization: urlParse(authEndpoint.URL),
		},
	}

	err := session.Redirect(w, r)

	assert.Nil(err)

	resp := w.Result()
	assert.Equal(http.StatusFound, resp.StatusCode)

	expectedRedirect := authEndpoint.URL +
		"?client_id=" + url.QueryEscape(clientEndpoint.URL) +
		"&me=https%3A%2F%2Fme.example.com" +
		"&redirect_uri=https%3A%2F%2Fwebapp.example.com%2Fcallback" +
		"&response_type=id" +
		"&state=1234"

	assert.Equal(expectedRedirect, resp.Header.Get("Location"))
}

func TestAuthenticationRedirectWithBadRedirectURIWhitelistedByTag(t *testing.T) {
	assert := assert.New(t)

	authEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

	}))
	defer authEndpoint.Close()

	clientEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
<head>
  <link rel="redirect_uri" href="https://webapp.example.com/callback" />
</head>
</html>`))
	}))
	defer clientEndpoint.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/somepath", nil)

	session := AuthenticationSession{
		Me:          urlParse("https://me.example.com"),
		ClientID:    urlParse(clientEndpoint.URL),
		RedirectURI: urlParse("https://webapp.example.com/callback"),
		State:       "1234",
		Endpoints: Endpoints{
			Authorization: urlParse(authEndpoint.URL),
		},
	}

	err := session.Redirect(w, r)

	assert.Nil(err)

	resp := w.Result()
	assert.Equal(http.StatusFound, resp.StatusCode)

	expectedRedirect := authEndpoint.URL +
		"?client_id=" + url.QueryEscape(clientEndpoint.URL) +
		"&me=https%3A%2F%2Fme.example.com" +
		"&redirect_uri=https%3A%2F%2Fwebapp.example.com%2Fcallback" +
		"&response_type=id" +
		"&state=1234"

	assert.Equal(expectedRedirect, resp.Header.Get("Location"))
}

func TestAuthenticationVerify(t *testing.T) {
	assert := assert.New(t)

	authEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" ||
			r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" ||
			r.FormValue("code") != "abcde" ||
			r.FormValue("client_id") != "http://localhost" ||
			r.FormValue("redirect_uri") != "http://localhost/callback" {
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"me": "http://john.doe"}`))
	}))
	defer authEndpoint.Close()

	session := AuthenticationSession{
		Me:          urlParse("http://me.localhost"),
		ClientID:    urlParse("http://localhost"),
		RedirectURI: urlParse("http://localhost/callback"),
		State:       "1234",
		Endpoints: Endpoints{
			Authorization: urlParse(authEndpoint.URL),
		},
	}

	me, err := session.Verify("abcde")

	assert.Nil(err)
	assert.Equal("http://john.doe", me)
}
