package indieauth

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

type Endpoints struct {
	Authorization *url.URL
	Token         *url.URL
}

func FindEndpoints(me *url.URL) (ends Endpoints, err error) {
	resp, err := http.Get(me.String())
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err = errors.New("bad response")
		return
	}

	root, err := html.Parse(resp.Body)
	if err != nil {
		return
	}

	var auth, token string

loop:
	for _, link := range searchAll(root, isLink) {
		for _, rel := range strings.Fields(getAttr(link, "rel")) {
			if rel == "authorization_endpoint" {
				auth = getAttr(link, "href")
				if token != "" {
					break loop
				}
			} else if rel == "token_endpoint" {
				token = getAttr(link, "href")
				if auth != "" {
					break loop
				}
			}
		}
	}

	authURL, err := url.Parse(auth)
	if err != nil {
		return
	}
	ends.Authorization = authURL

	tokenURL, err := url.Parse(token)
	if err != nil {
		return
	}
	ends.Token = tokenURL

	return
}
