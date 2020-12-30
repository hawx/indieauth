package indieauth

import (
	"strings"

	"github.com/tomnomnom/linkheader"
	"golang.org/x/net/html"
)

func findLinks(node *html.Node) linkheader.Links {
	var links linkheader.Links

	for _, link := range searchAll(node, isLink) {
		for _, rel := range strings.Fields(getAttr(link, "rel")) {
			links = append(links, linkheader.Link{
				Rel: rel,
				URL: getAttr(link, "href"),
			})
		}
	}

	return links
}

func searchAll(node *html.Node, pred func(*html.Node) bool) (results []*html.Node) {
	if pred(node) {
		results = append(results, node)
		return
	}

	for child := node.FirstChild; child != nil; child = child.NextSibling {
		result := searchAll(child, pred)
		if len(result) > 0 {
			results = append(results, result...)
		}
	}

	return
}

func isLink(node *html.Node) bool {
	return node.Type == html.ElementNode && node.Data == "link"
}

func getAttr(node *html.Node, attrName string) string {
	for _, attr := range node.Attr {
		if attr.Key == attrName {
			return attr.Val
		}
	}

	return ""
}
