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

type AuthenticationSession struct {
	Me          *url.URL
	ClientID    *url.URL
	RedirectURI *url.URL
	State       string
	Endpoints   Endpoints
}

func (sess AuthenticationSession) Redirect(w http.ResponseWriter, r *http.Request) error {
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
			"response_type": {"id"},
		}.Encode(),
	}

	redirectURI := sess.Endpoints.Authorization.ResolveReference(queryURL)

	http.Redirect(w, r, redirectURI.String(), http.StatusFound)

	return nil
}

func (sess AuthenticationSession) Verify(code string) (me string, err error) {
	req, err := http.NewRequest("POST", sess.Endpoints.Authorization.String(), strings.NewReader(url.Values{
		"code":         {code},
		"client_id":    {sess.ClientID.String()},
		"redirect_uri": {sess.RedirectURI.String()},
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
		return "", errors.New("recieved a bad request")
	}

	var data struct {
		Me string `json:"me"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}

	return data.Me, nil
}
