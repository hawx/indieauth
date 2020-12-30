// Package indieauth provides support for authorization using IndieAuth.
//
// See https://indieauth.spec.indieweb.org/
package indieauth

import (
	"encoding/json"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

// Config defines a client for authorizing users to perform a set of defined
// actions.
type Config struct {
	ClientID    string
	RedirectURL string
	Scopes      []string
	Client      *http.Client
}

// AuthCodeURL returns a URL to the authorization provider.
func (c *Config) AuthCodeURL(endpoints Endpoints, state, codeChallenge, me string) string {
	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.ClientID},
		"redirect_uri":          {c.RedirectURL},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}

	if me != "" {
		form.Set("me", me)
	}

	if len(c.Scopes) > 0 {
		form.Set("scope", strings.Join(c.Scopes, " "))
	}

	queryURL := &url.URL{
		RawQuery: form.Encode(),
	}

	return endpoints.Authorization.ResolveReference(queryURL).String()
}

// Exchange converts an authorization code into a token or profile
// information. The code will be in the query string of the request sent to the
// RedirectURL, before calling this method ensure you check the state parameter
// matches the value used for AuthCodeURL.
//
// If Scopes is empty, "profile", or "profile email", the response will not
// contain an access token.
func (c *Config) Exchange(endpoints Endpoints, codeVerifier, code string) (*Response, error) {
	client := http.DefaultClient
	if c.Client != nil {
		client = c.Client
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {c.ClientID},
		"redirect_uri":  {c.RedirectURL},
		"code_verifier": {codeVerifier},
	}

	endpoint := endpoints.Token
	if c.isProfile() {
		endpoint = endpoints.Authorization
	}

	req, err := http.NewRequest("POST", endpoint.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	mediatype, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode != http.StatusOK || mediatype != "application/json" {
		data, _ := ioutil.ReadAll(resp.Body)
		return nil, &RequestError{
			StatusCode: resp.StatusCode,
			MediaType:  mediatype,
			Body:       data,
		}
	}

	var data struct {
		AccessToken string                 `json:"access_token"`
		TokenType   string                 `json:"token_type"`
		Scope       string                 `json:"scope"`
		Me          string                 `json:"me"`
		Profile     map[string]interface{} `json:"profile"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	newEndpoints, err := c.FindEndpoints(data.Me)
	if err != nil {
		return nil, err
	}

	if newEndpoints.Authorization.String() != endpoints.Authorization.String() {
		return nil, ErrCannotClaim
	}

	return &Response{
		AccessToken: data.AccessToken,
		TokenType:   data.TokenType,
		Scopes:      strings.Fields(data.Scope),
		Me:          data.Me,
		Profile:     data.Profile,
	}, nil
}

func (c *Config) isProfile() bool {
	switch len(c.Scopes) {
	case 0:
		return true
	case 1:
		return c.Scopes[0] == "profile"
	case 2:
		return c.Scopes[0] == "profile" && c.Scopes[1] == "email" ||
			c.Scopes[0] == "email" && c.Scopes[1] == "profile"
	default:
		return false
	}
}
