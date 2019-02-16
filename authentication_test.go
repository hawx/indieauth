package indieauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"hawx.me/code/assert"
)

func TestAuthenticationRedirect(t *testing.T) {
	assert := assert.New(t)

	authEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

	}))
	defer authEndpoint.Close()

	session := &AuthenticationConfig{
		ClientID:    urlParse("https://webapp.example.com/"),
		RedirectURI: urlParse("https://webapp.example.com/callback"),
	}

	endpoints := Endpoints{
		Authorization: urlParse(authEndpoint.URL),
	}

	redirectURL := session.RedirectURL(endpoints, "https://me.example.com", "1234")

	expectedRedirect := authEndpoint.URL +
		"?client_id=https%3A%2F%2Fwebapp.example.com%2F" +
		"&me=https%3A%2F%2Fme.example.com" +
		"&redirect_uri=https%3A%2F%2Fwebapp.example.com%2Fcallback" +
		"&response_type=id" +
		"&state=1234"

	assert.Equal(expectedRedirect, redirectURL)
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

	session := &AuthenticationConfig{
		ClientID:    urlParse("http://localhost"),
		RedirectURI: urlParse("http://localhost/callback"),
	}

	endpoints := Endpoints{
		Authorization: urlParse(authEndpoint.URL),
	}

	me, err := session.Exchange(endpoints, "abcde")

	assert.Nil(err)
	assert.Equal("http://john.doe", me)
}
