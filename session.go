package indieauth

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/peterhellberg/link"
	"golang.org/x/net/html"
)

func verifySession(me, clientID, redirectURI *url.URL) bool {
	if clientID.Scheme == redirectURI.Scheme && clientID.Host == redirectURI.Host {
		return true
	}

	clientResp, err := http.Get(clientID.String())
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

	redirect := redirectURI.String()
	for _, candidate := range whitelist {
		if candidate == redirect {
			return true
		}
	}

	return false
}
