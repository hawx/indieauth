package indieauth

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/peterhellberg/link"
	"golang.org/x/net/html"
)

type Session struct {
	Me          *url.URL
	ClientID    *url.URL
	RedirectURI *url.URL
	State       string
	Endpoints   Endpoints
}

func (sess Session) Verify() bool {
	if sess.ClientID.Scheme == sess.RedirectURI.Scheme && sess.ClientID.Host == sess.RedirectURI.Host {
		return true
	}

	clientResp, err := http.Get(sess.ClientID.String())
	if err != nil {
		return false
	}
	defer clientResp.Body.Close()

	if clientResp.StatusCode < 200 && clientResp.StatusCode >= 300 {
		return false
	}

	var whitelist []string

	if whitelistedRedirect, ok := link.ParseResponse(clientResp)["redirect_uri"]; ok {
		whitelist = append(whitelist, whitelistedRedirect.URI)
	}

	if root, err := html.Parse(clientResp.Body); err == nil {
		redirectLinks := searchAll(root, func(node *html.Node) bool {
			if node.Type == html.ElementNode && node.Data == "link" {
				rels := strings.Fields(getAttr(node, "rel"))
				for _, rel := range rels {
					if rel == "redirect_uri" {
						return true
					}
				}
			}

			return false
		})

		for _, node := range redirectLinks {
			whitelist = append(whitelist, getAttr(node, "href"))
		}
	}

	redirectURI := sess.RedirectURI.String()
	for _, candidate := range whitelist {
		if candidate == redirectURI {
			return true
		}
	}

	return false
}
