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

func FindEndpoints(me string) (ends Endpoints, err error) {
	meURL, err := url.Parse(me)
	if err != nil {
		return
	}

	resp, err := http.DefaultClient.Get(me)
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

loop:
	for _, link := range searchAll(root, isLink) {
		for _, rel := range strings.Fields(getAttr(link, "rel")) {
			if rel == "authorization_endpoint" {
				if auth := getAttr(link, "href"); auth != "" {
					authURL, err := meURL.Parse(auth)
					if err != nil {
						return ends, err
					}
					ends.Authorization = authURL

					if ends.Token != nil {
						break loop
					}
				}
			} else if rel == "token_endpoint" {
				if token := getAttr(link, "href"); token != "" {
					tokenURL, err := meURL.Parse(token)
					if err != nil {
						return ends, err
					}
					ends.Token = tokenURL

					if ends.Authorization != nil {
						break loop
					}
				}
			}
		}
	}

	if ends.Authorization == nil {
		return ends, ErrAuthorizationEndpointMissing
	}

	return
}
