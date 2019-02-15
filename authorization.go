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

type AuthorizationSession struct {
	Me          *url.URL
	ClientID    *url.URL
	RedirectURI *url.URL
	Scopes      []string
	State       string
	Endpoints   Endpoints
}

func (sess AuthorizationSession) Redirect(w http.ResponseWriter, r *http.Request) error {
	if r.Method != "GET" {
		return errors.New("can only redirect from GET requests")
	}

	if !verifySession(sess.Me, sess.ClientID, sess.RedirectURI) {
		http.Error(w, "client_id and redirect_uri are suspicious", http.StatusBadRequest)
		return errors.New("ClientID and RedirectURI are suspicios")
	}

	queryURL := &url.URL{
		RawQuery: url.Values{
			"me":            {sess.Me.String()},
			"client_id":     {sess.ClientID.String()},
			"redirect_uri":  {sess.RedirectURI.String()},
			"state":         {sess.State},
			"response_type": {"code"},
			"scope":         {strings.Join(sess.Scopes, " ")},
		}.Encode(),
	}

	redirectURI := sess.Endpoints.Authorization.ResolveReference(queryURL)

	http.Redirect(w, r, redirectURI.String(), http.StatusFound)

	return nil
}

func (sess AuthorizationSession) Verify(code string) (token Token, err error) {
	req, err := http.NewRequest("POST", sess.Endpoints.Authorization.String(), strings.NewReader(url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"client_id":    {sess.ClientID.String()},
		"redirect_uri": {sess.RedirectURI.String()},
		"me":           {sess.Me.String()},
	}.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
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
