package indieauth_test

import (
	"net/http"

	"hawx.me/code/indieauth/v2"
)

func ExampleAuthorization() {
	randomString := func() string {
		return "abcde"
	}

	setCookie := func(w http.ResponseWriter, r *http.Request, token indieauth.Token) {
		// more code...
	}

	sessions := map[string]indieauth.Endpoints{}
	mes := map[string]string{}

	// get the configuration for authorization, the only difference to
	// authentication is that we are asking the user to allow us to perform
	// certain actions: here 'create' and 'update'
	config, _ := indieauth.Authorization(
		"http://client.example.com/",
		"http://client.example.com/callback",
		[]string{"create", "update"})

	http.HandleFunc("/sign-in", func(w http.ResponseWriter, r *http.Request) {
		state := randomString()

		endpoints, _ := indieauth.FindEndpoints(r.FormValue("me"))
		sessions[state] = endpoints
		// we need to store the user's profile URL as it is needed for the exchange
		// in this flow
		mes[state] = r.FormValue("me")

		redirectURL := config.RedirectURL(endpoints, r.FormValue("me"), "some-random-state")

		http.Redirect(w, r, redirectURL, http.StatusFound)
	})

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		state := r.FormValue("state")

		endpoints, ok := sessions[state]
		if !ok {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		me := mes[state]

		// authorization results in a token which we can then use to perform actions
		// on behalf of the authenticated user
		token, err := config.Exchange(endpoints, r.FormValue("code"), me)
		if err != nil {
			http.Redirect(w, r, "/?error", http.StatusFound)
			return
		}

		setCookie(w, r, token)
		http.Redirect(w, r, "/", http.StatusFound)
	})
}
