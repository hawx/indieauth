package indieauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
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

	homepageURL, _ := url.Parse(homepage.URL)
	endpoints, err := FindEndpoints(homepageURL)

	assert.Nil(t, err)
	assert.Equal(t, "http://example.com/hey", endpoints.Authorization.String())
	assert.Equal(t, "http://example.com/what", endpoints.Token.String())
}
