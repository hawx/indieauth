package indieauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"hawx.me/code/assert"
)

func TestFindEndpoints(t *testing.T) {
	homepage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`
<html>
<head>
<link rel="authorization_endpoint" href="http://example.com/hey" />
<link rel="token_endpoint" href="http://example.com/what" />
</head>
</html>
`))
	}))
	defer homepage.Close()

	endpoints, err := FindEndpoints(homepage.URL)

	assert.Nil(t, err)
	assert.Equal(t, "http://example.com/hey", endpoints.Authorization.String())
	assert.Equal(t, "http://example.com/what", endpoints.Token.String())
}

func TestFindEndpointsRelative(t *testing.T) {
	homepage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`
<html>
<head>
<link rel="authorization_endpoint" href="/hey" />
<link rel="token_endpoint" href="what" />
</head>
</html>
`))
	}))
	defer homepage.Close()

	endpoints, err := FindEndpoints(homepage.URL)

	assert.Nil(t, err)
	assert.Equal(t, homepage.URL+"/hey", endpoints.Authorization.String())
	assert.Equal(t, homepage.URL+"/what", endpoints.Token.String())
}
