package indieauth_test

import (
	"fmt"
	"log"
	"net/http"

	"hawx.me/code/indieauth/v2"
)

func ExampleNewSessions() {
	sessions, _ := indieauth.NewSessions("7xZ+h4OnB0EkgSDspZila2fvn5c0ggE+xmBz9VpyfGU=", &indieauth.Config{
		ClientID:    "http://localhost:8080/",
		RedirectURL: "http://localhost:8080/callback",
	})

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if response, ok := sessions.SignedIn(r); ok {
			fmt.Fprintf(w, `Signed in as: %s<br/><a href="/sign-out">Sign-out</a>`, response.Me)
		} else {
			fmt.Fprint(w, `<form action="/sign-in"><input name="me"><button type="submit">Sign-in</button>`)
		}
	})

	mux.HandleFunc("/sign-in", func(w http.ResponseWriter, r *http.Request) {
		if err := sessions.RedirectToSignIn(w, r, r.FormValue("me")); err != nil {
			log.Println(err)
			http.Error(w, "", http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if err := sessions.HandleCallback(w, r); err != nil {
			log.Println(err)
			http.Error(w, "", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusFound)
	})

	mux.HandleFunc("/sign-out", func(w http.ResponseWriter, r *http.Request) {
		if err := sessions.SignOut(w, r); err != nil {
			log.Println(err)
			http.Error(w, "", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusFound)
	})

	log.Println("Listening at :8080")
	http.ListenAndServe(":8080", mux)
}
