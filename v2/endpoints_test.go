package indieauth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"hawx.me/code/assert"
)

func testEndpointServer(body string, headers http.Header) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, vs := range headers {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, body)
	}))
}

func testMetadataEndpoint(body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
}

func TestFindEndpoints(t *testing.T) {
	homepage := testEndpointServer(`
<html>
<head>
<link rel="authorization_endpoint" href="http://example.com/hey" />
<link rel="token_endpoint" href="http://example.com/what" />
</head>
</html>
`, nil)
	defer homepage.Close()

	endpoints, err := (&Config{}).FindEndpoints(homepage.URL)

	if assert.Nil(t, err) {
		assert.Equal(t, "http://example.com/hey", endpoints.Authorization.String())
		assert.Equal(t, "http://example.com/what", endpoints.Token.String())
	}
}

func TestFindEndpointsUseFirst(t *testing.T) {
	homepage := testEndpointServer(`
<html>
<head>
<link rel="authorization_endpoint" href="http://example.com/hey" />
<link rel="token_endpoint" href="http://example.com/what" />
<link rel="authorization_endpoint" href="http://example.com/hey2" />
<link rel="token_endpoint" href="http://example.com/what2" />
</head>
</html>
`, nil)
	defer homepage.Close()

	endpoints, err := (&Config{}).FindEndpoints(homepage.URL)

	if assert.Nil(t, err) {
		assert.Equal(t, "http://example.com/hey", endpoints.Authorization.String())
		assert.Equal(t, "http://example.com/what", endpoints.Token.String())
	}
}

func TestFindEndpointsSame(t *testing.T) {
	homepage := testEndpointServer(`
<html>
<head>
<link rel="authorization_endpoint token_endpoint" href="http://example.com/hey" />
</head>
</html>
`, nil)
	defer homepage.Close()

	endpoints, err := (&Config{}).FindEndpoints(homepage.URL)

	if assert.Nil(t, err) {
		assert.Equal(t, "http://example.com/hey", endpoints.Authorization.String())
		assert.Equal(t, "http://example.com/hey", endpoints.Token.String())
	}
}

func TestFindEndpointsRelative(t *testing.T) {
	homepage := testEndpointServer(`
<html>
<head>
<link rel="authorization_endpoint" href="/hey" />
<link rel="token_endpoint" href="what" />
</head>
</html>
`, nil)
	defer homepage.Close()

	endpoints, err := (&Config{}).FindEndpoints(homepage.URL)

	if assert.Nil(t, err) {
		assert.Equal(t, homepage.URL+"/hey", endpoints.Authorization.String())
		assert.Equal(t, homepage.URL+"/what", endpoints.Token.String())
	}
}

func TestFindEndpointsLink(t *testing.T) {
	homepage := testEndpointServer("", http.Header{
		"Link": {
			`<http://example.com/hey>; rel="authorization_endpoint"`,
			`<http://example.com/what>; rel="token_endpoint"`,
		},
	})
	defer homepage.Close()

	endpoints, err := (&Config{}).FindEndpoints(homepage.URL)

	if assert.Nil(t, err) {
		assert.Equal(t, "http://example.com/hey", endpoints.Authorization.String())
		assert.Equal(t, "http://example.com/what", endpoints.Token.String())
	}
}

func TestFindEndpointsLinkJoined(t *testing.T) {
	homepage := testEndpointServer("", http.Header{
		"Link": {
			`<http://example.com/hey>; rel="authorization_endpoint", <http://example.com/what>; rel="token_endpoint"`,
		},
	})
	defer homepage.Close()

	endpoints, err := (&Config{}).FindEndpoints(homepage.URL)

	if assert.Nil(t, err) {
		assert.Equal(t, "http://example.com/hey", endpoints.Authorization.String())
		assert.Equal(t, "http://example.com/what", endpoints.Token.String())
	}
}

func TestFindEndpointsPreferLink(t *testing.T) {
	homepage := testEndpointServer(`
<html>
<head>
<link rel="authorization_endpoint" href="http://example.com/hey2" />
<link rel="token_endpoint" href="http://example.com/what2" />
</head>
</html>
`, http.Header{
		"Link": {
			`<http://example.com/hey>; rel="authorization_endpoint"`,
			`<http://example.com/what>; rel="token_endpoint"`,
		},
	})
	defer homepage.Close()

	endpoints, err := (&Config{}).FindEndpoints(homepage.URL)

	if assert.Nil(t, err) {
		assert.Equal(t, "http://example.com/hey", endpoints.Authorization.String())
		assert.Equal(t, "http://example.com/what", endpoints.Token.String())
	}
}

func TestFindMissing(t *testing.T) {
	homepage := testEndpointServer(`
<html>
<head>
</head>
</html>
`, nil)
	defer homepage.Close()

	_, err := (&Config{}).FindEndpoints(homepage.URL)

	assert.Equal(t, ErrAuthorizationEndpointMissing, err)
}

func TestFindEndpointsViaMetadata(t *testing.T) {
	metadata := testMetadataEndpoint(`
{
	"authorization_endpoint":  "http://example.com/not-hey",
	"token_endpoint": "http://example.com/not-what"
}
`)

	defer metadata.Close()

	homepage := testEndpointServer(`
<html>
<head>
<link rel="indieauth-metadata" href="`+metadata.URL+`" />
<link rel="authorization_endpoint" href="http://example.com/hey" />
<link rel="token_endpoint" href="http://example.com/what" />
</head>
</html>
`, nil)
	defer homepage.Close()

	endpoints, err := (&Config{}).FindEndpoints(homepage.URL)

	if assert.Nil(t, err) {
		assert.Equal(t, "http://example.com/not-hey", endpoints.Authorization.String())
		assert.Equal(t, "http://example.com/not-what", endpoints.Token.String())
	}
}

func TestFindEndpointsViaMetadataLink(t *testing.T) {
	metadata := testMetadataEndpoint(`
{
	"authorization_endpoint":  "http://example.com/not-hey",
	"token_endpoint": "http://example.com/not-what"
}
`)
	defer metadata.Close()

	homepage := testEndpointServer("", http.Header{
		"Link": {
			`<` + metadata.URL + `>; rel="indieauth-metadata"`,
		},
	})
	defer homepage.Close()

	endpoints, err := (&Config{}).FindEndpoints(homepage.URL)

	if assert.Nil(t, err) {
		assert.Equal(t, "http://example.com/not-hey", endpoints.Authorization.String())
		assert.Equal(t, "http://example.com/not-what", endpoints.Token.String())
	}
}

func TestFindEndpointsViaMetadataPreferLink(t *testing.T) {
	metadata := testMetadataEndpoint(`
{
	"authorization_endpoint":  "http://example.com/hey",
	"token_endpoint": "http://example.com/what"
}
`)
	defer metadata.Close()

	homepage := testEndpointServer(`
<html>
<head>
<link rel="indieauth-metadata" href="http://example.com/not-valid" />
</head>
</html>
`, http.Header{
		"Link": {
			`<` + metadata.URL + `>; rel="indieauth-metadata"`,
		},
	})
	defer homepage.Close()

	endpoints, err := (&Config{}).FindEndpoints(homepage.URL)

	if assert.Nil(t, err) {
		assert.Equal(t, "http://example.com/hey", endpoints.Authorization.String())
		assert.Equal(t, "http://example.com/what", endpoints.Token.String())
	}

}
