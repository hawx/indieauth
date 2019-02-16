package indieauth

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

type Token struct {
	AccessToken string
	TokenType   string
	Scopes      []string
	Me          string
}

func (t Token) HasScope(scope string) bool {
	for _, candidate := range t.Scopes {
		if candidate == scope {
			return true
		}
	}

	return false
}

// AuthorizationConfig defines configuration for a client making requests to
// authorize a user to perform a set of defined actions.
type AuthorizationConfig struct {
	ClientID    *url.URL
	RedirectURI *url.URL
	Scopes      []string
	Client      *http.Client
}

func Authorization(clientID, redirectURI string, scopes []string) (*AuthorizationConfig, error) {
	clientURL, err := url.Parse(clientID)
	if err != nil {
		return nil, err
	}
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		return nil, err
	}

	return &AuthorizationConfig{
		ClientID:    clientURL,
		RedirectURI: redirectURL,
		Scopes:      scopes,
		Client:      http.DefaultClient,
	}, nil
}

// RedirectURL returns a URL to the authorization provider for the profile URL,
// or "me", given.
func (c *AuthorizationConfig) RedirectURL(endpoints Endpoints, me, state string) string {
	queryURL := &url.URL{
		RawQuery: url.Values{
			"me":            {me},
			"client_id":     {c.ClientID.String()},
			"redirect_uri":  {c.RedirectURI.String()},
			"state":         {state},
			"response_type": {"code"},
			"scope":         {strings.Join(c.Scopes, " ")},
		}.Encode(),
	}

	redirectURI := endpoints.Authorization.ResolveReference(queryURL)
	return redirectURI.String()
}

// Exchange converts an authorization code into a token. The code will usually
// be in r.FormValue("code"), but before calling this method be sure to check
// the value of r.FormValue("state") is as expected.
func (c *AuthorizationConfig) Exchange(endpoints Endpoints, code, me string) (token Token, err error) {
	client := http.DefaultClient
	if c.Client != nil {
		client = c.Client
	}

	req, err := http.NewRequest("POST", endpoints.Authorization.String(), strings.NewReader(url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"client_id":    {c.ClientID.String()},
		"redirect_uri": {c.RedirectURI.String()},
		"me":           {me},
	}.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	mediatype, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode != http.StatusOK || mediatype != "application/json" {
		data, _ := ioutil.ReadAll(resp.Body)
		log.Println(string(data))
		return token, errors.New("recieved a bad request")
	}

	var data struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
		Me          string `json:"me"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return token, err
	}

	token.AccessToken = data.AccessToken
	token.TokenType = data.TokenType
	token.Scopes = strings.Fields(data.Scope)
	token.Me = data.Me

	return token, nil
}
