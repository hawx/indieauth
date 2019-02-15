package main

import (
	"log"
	"net/http"
	"net/url"

	indieauth "hawx.me/code/indie-auth"
)

func main() {
	sessions := map[string]indieauth.AuthenticationSession{}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`
<html>
  <body>
    <form action="/redirect" method="get">
      <label for="me">Your URL:</label>
      <input id="me" name="me" placeholder="e.g. https://example.com" />
      <button type="submit">Sign-in</button>
    </form>
  </body>
</html>
`))
	})

	http.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		meURL, err := url.Parse(r.FormValue("me"))
		if err != nil {
			log.Println(err)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		ends, err := indieauth.FindEndpoints(meURL)
		if err != nil {
			log.Println(err)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		sess := indieauth.AuthenticationSession{
			Me:          meURL,
			ClientID:    urlParse("http://localhost:8080/"),
			RedirectURI: urlParse("http://localhost:8080/callback"),
			State:       "1234",
			Endpoints:   ends,
		}
		sessions["1234"] = sess

		err = sess.Redirect(w, r)

		if err != nil {
			log.Println(err)
		}
	})

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		state := r.FormValue("state")

		sess, ok := sessions[state]
		if !ok {
			log.Println("did you even start?")
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		me, err := sess.Verify(r.FormValue("code"))
		if err != nil {
			log.Println(err)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		w.Write([]byte(me))
	})

	http.ListenAndServe(":8080", nil)
}

func urlParse(s string) *url.URL {
	u, _ := url.Parse(s)
	return u
}
