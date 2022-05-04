package indieauth

import (
	"encoding/json"
	"mime"
	"net/http"
	"net/url"

	"github.com/tomnomnom/linkheader"
	"golang.org/x/net/html"
)

type Endpoints struct {
	Authorization *url.URL
	Token         *url.URL
}

// FindEndpoints retrieves the defined authorization and token endpoints for
// 'me'. As an authorization endpoint must exist to authenticate a user
// ErrAuthorizationEndpointMissing will be returned if one cannot be found.
func (c *Config) FindEndpoints(me string) (Endpoints, error) {
	var endpoints Endpoints

	client := http.DefaultClient
	if c.Client != nil {
		client = c.Client
	}

	meURL, err := url.Parse(me)
	if err != nil {
		return endpoints, err
	}

	resp, err := client.Get(meURL.String())
	if err != nil {
		return endpoints, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return endpoints, &RequestError{
			StatusCode: resp.StatusCode,
		}
	}

	links := linkheader.ParseMultiple(resp.Header["Link"])

	mediatype, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if mediatype == "text/html" {
		root, err := html.Parse(resp.Body)
		if err == nil {
			links = append(links, findLinks(root)...)
		}
	}

	metadataEndpoints := links.FilterByRel("indieauth-metadata")
	if len(metadataEndpoints) != 0 {
		linkURL, err := meURL.Parse(metadataEndpoints[0].URL)
		if err != nil {
			return endpoints, err
		}

		endpoints, err = c.findByDiscoveryEndpoint(client, linkURL)
	} else {
		endpoints, err = c.findDirectly(meURL, links)
	}

	if err != nil {
		return endpoints, err
	}

	if endpoints.Authorization == nil {
		return endpoints, ErrAuthorizationEndpointMissing
	}

	return endpoints, nil
}

type metadata struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

func (c *Config) findByDiscoveryEndpoint(client *http.Client, url *url.URL) (Endpoints, error) {
	var endpoints Endpoints

	resp, err := client.Get(url.String())
	if err != nil {
		return endpoints, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return endpoints, &RequestError{
			StatusCode: resp.StatusCode,
		}
	}

	var v metadata
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return endpoints, err
	}

	linkURL, err := url.Parse(v.AuthorizationEndpoint)
	if err == nil {
		endpoints.Authorization = linkURL
	}

	linkURL, err = url.Parse(v.TokenEndpoint)
	if err == nil {
		endpoints.Token = linkURL
	}

	return endpoints, nil
}

func (c *Config) findDirectly(url *url.URL, links []linkheader.Link) (endpoints Endpoints, err error) {
	for _, link := range links {
		if link.Rel == "authorization_endpoint" && endpoints.Authorization == nil {
			linkURL, err := url.Parse(link.URL)
			if err != nil {
				return endpoints, err
			}
			endpoints.Authorization = linkURL
		}

		if link.Rel == "token_endpoint" && endpoints.Token == nil {
			linkURL, err := url.Parse(link.URL)
			if err != nil {
				return endpoints, err
			}
			endpoints.Token = linkURL
		}

		if endpoints.Authorization != nil && endpoints.Token != nil {
			return endpoints, nil
		}
	}

	return endpoints, err
}
