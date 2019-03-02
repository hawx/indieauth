// Package sessions implements some helpers for getting started with indieauth.
//
// This is basically a wrapper for gorilla/sessions, some handlers for sign-in,
// callback and sign-out, and a couple of handlers for protecting routes. It
// assumes you only need to authenticate a single user.
package sessions

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"

	"github.com/gorilla/sessions"
	"hawx.me/code/indieauth"
)

// Sessions provides some handlers for authenticating a single user with
// indieauth.
type Sessions struct {
	me    string
	store sessions.Store
	auth  *indieauth.AuthenticationConfig
	ends  indieauth.Endpoints
	// Handler to use when Shield fails
	DefaultSignedOut http.Handler
	// Path to redirect to on sign-in/out
	Root string
}

// New creates a new Sessions.
func New(me, secret string, auth *indieauth.AuthenticationConfig) (*Sessions, error) {
	if me == "" {
		return nil, errors.New("me must be non-empty")
	}

	endpoints, err := indieauth.FindEndpoints(me)
	if err != nil {
		return nil, err
	}

	return &Sessions{
		me:               me,
		store:            sessions.NewCookieStore([]byte(secret)),
		auth:             auth,
		ends:             endpoints,
		DefaultSignedOut: http.NotFoundHandler(),
		Root:             "/",
	}, nil
}

func (s *Sessions) get(r *http.Request) string {
	session, _ := s.store.Get(r, "session")

	if v, ok := session.Values["me"].(string); ok {
		return v
	}

	return ""
}

func (s *Sessions) set(w http.ResponseWriter, r *http.Request, me string) {
	session, _ := s.store.Get(r, "session")
	session.Values["me"] = me
	session.Save(r, w)
}

func (s *Sessions) setState(w http.ResponseWriter, r *http.Request) (string, error) {
	bytes := make([]byte, 32)

	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}

	state := base64.StdEncoding.EncodeToString(bytes)

	session, _ := s.store.Get(r, "session")
	session.Values["state"] = state
	return state, session.Save(r, w)
}

func (s *Sessions) getState(r *http.Request) string {
	session, _ := s.store.Get(r, "session")

	if v, ok := session.Values["state"].(string); ok {
		return v
	}

	return ""
}

// Choose allows you to switch between two handlers depending on whether the
// expected user is signed in or not.
func (s *Sessions) Choose(signedIn, signedOut http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if addr := s.get(r); addr == s.me {
			signedIn.ServeHTTP(w, r)
		} else {
			signedOut.ServeHTTP(w, r)
		}
	})
}

// Shield will let the request continue if the expected user is signed in,
// otherwise they will be shown the DefaultSignedOut handler.
func (s *Sessions) Shield(signedIn http.Handler) http.HandlerFunc {
	return s.Choose(signedIn, s.DefaultSignedOut)
}

// SignIn should be assigned to a route like /sign-in, it redirects users to the
// correct endpoint.
func (s *Sessions) SignIn() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, err := s.setState(w, r)
		if err != nil {
			http.Error(w, "could not start auth", http.StatusInternalServerError)
			return
		}

		redirectURL := s.auth.RedirectURL(s.ends, s.me, state)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, redirectURL, http.StatusFound)
	}
}

// Callback should be assigned to the redirectURL you configured for indieauth.
func (s *Sessions) Callback() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state := s.getState(r)

		if r.FormValue("state") != state {
			http.Error(w, "state is bad", http.StatusBadRequest)
			return
		}

		me, err := s.auth.Exchange(s.ends, r.FormValue("code"))
		if err != nil || me != s.me {
			http.Error(w, "nope", http.StatusForbidden)
			return
		}

		s.set(w, r, me)
		http.Redirect(w, r, s.Root, http.StatusFound)
	}
}

// SignOut will remove the session cookie for the user.
func (s *Sessions) SignOut() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.set(w, r, "")
		http.Redirect(w, r, s.Root, http.StatusFound)
	}
}
