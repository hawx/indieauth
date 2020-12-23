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

var errCannotClaim = errors.New("me returned with non-matching authorization endpoint")

// AuthenticationConfig provides the data for a client that wants to
// authenticate users.
type AuthenticationConfig struct {
	ClientID    *url.URL
	RedirectURI *url.URL
	Client      *http.Client
}

func Authentication(clientID, redirectURI string) (*AuthenticationConfig, error) {
	clientURL, err := url.Parse(clientID)
	if err != nil {
		return nil, err
	}
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		return nil, err
	}

	return &AuthenticationConfig{
		ClientID:    clientURL,
		RedirectURI: redirectURL,
		Client:      http.DefaultClient,
	}, nil
}

// RedirectURL returns a URL to the authorization provider for the profile URL,
// or "me", given.
func (c *AuthenticationConfig) RedirectURL(endpoints Endpoints, me, state string) string {
	queryURL := &url.URL{
		RawQuery: url.Values{
			"me":            {me},
			"client_id":     {c.ClientID.String()},
			"redirect_uri":  {c.RedirectURI.String()},
			"state":         {state},
			"response_type": {"id"},
		}.Encode(),
	}

	redirectURI := endpoints.Authorization.ResolveReference(queryURL)
	return redirectURI.String()
}

// Exchange converts an authentication code into the profile URL, or "me". The
// code will usually be in r.FormValue("code"), but before calling this method
// be sure to check the value of r.FormValue("state") is as expected.
func (c *AuthenticationConfig) Exchange(endpoints Endpoints, code string) (me string, err error) {
	client := http.DefaultClient
	if c.Client != nil {
		client = c.Client
	}

	req, err := http.NewRequest("POST", endpoints.Authorization.String(), strings.NewReader(url.Values{
		"code":         {code},
		"client_id":    {c.ClientID.String()},
		"redirect_uri": {c.RedirectURI.String()},
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
		return "", errors.New("recieved a bad request")
	}

	var data struct {
		Me string `json:"me"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}

	newEndpoints, err := FindEndpoints(data.Me)
	if err != nil {
		return "", err
	}

	if newEndpoints.Authorization.String() != endpoints.Authorization.String() {
		return "", errCannotClaim
	}

	return data.Me, nil
}
