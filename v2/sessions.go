package indieauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/sessions"
)

type sessionData struct {
	State     string
	Verifier  string
	Endpoints Endpoints
}

func init() {
	gob.Register(sessionData{})
	gob.Register(Response{})
}

type Sessions struct {
	store  sessions.Store
	config *Config
}

// NewSessions creates a new session handler that uses cookies to store the
// current user. The secret should be 32 or 64 bytes base64 encoded.
func NewSessions(secret string, config *Config) (*Sessions, error) {
	byteSecret, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, err
	}

	return &Sessions{
		store:  sessions.NewCookieStore(byteSecret),
		config: config,
	}, nil
}

// RedirectToSignIn will issue a redirect to the authorization endpoint
// discovered for "me".
func (s *Sessions) RedirectToSignIn(w http.ResponseWriter, r *http.Request, me string) error {
	endpoints, err := FindEndpoints(me)
	if err != nil {
		return fmt.Errorf("could not find authorization endpoints: %w", err)
	}

	state, err := randomString()
	if err != nil {
		return err
	}

	verifier, err := randomString()
	if err != nil {
		return err
	}

	err = s.setData(w, r, sessionData{
		State:     state,
		Verifier:  verifier,
		Endpoints: endpoints,
	})
	if err != nil {
		return err
	}

	redirectURL := s.config.AuthCodeURL(endpoints, state, s256(verifier), me)
	if err != nil {
		return fmt.Errorf("could not build redirect url: %w", err)
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
	return nil
}

// HandleCallback will complete the authentication process and should be called
// in the route assigned to RedirectURL. After calling this, redirect to another
// page of your application.
func (s *Sessions) HandleCallback(w http.ResponseWriter, r *http.Request) error {
	data := s.getData(r)

	if r.FormValue("state") != data.State {
		return fmt.Errorf("unexpected state")
	}

	response, err := s.config.Exchange(data.Endpoints, data.Verifier, r.FormValue("code"))
	if err != nil {
		return fmt.Errorf("code exchange failed: %w", err)
	}

	return s.set(w, r, response)
}

// SignOut will remove the session cookie for the user.
func (s *Sessions) SignOut(w http.ResponseWriter, r *http.Request) error {
	return s.set(w, r, &Response{})
}

// SignedIn will return the response for the current session, if signed in.
func (s *Sessions) SignedIn(r *http.Request) (*Response, bool) {
	response := s.get(r)
	return response, response != nil && response.Me != ""
}

func (s *Sessions) get(r *http.Request) *Response {
	session, _ := s.store.Get(r, "session")
	response, _ := session.Values["response"].(Response)

	return &response
}

func (s *Sessions) set(w http.ResponseWriter, r *http.Request, response *Response) error {
	session, _ := s.store.Get(r, "session")
	session.Values = map[interface{}]interface{}{
		"response": response,
	}

	return session.Save(r, w)
}

func (s *Sessions) setData(w http.ResponseWriter, r *http.Request, data sessionData) error {
	session, _ := s.store.Get(r, "session")
	session.Values = map[interface{}]interface{}{
		"data": data,
	}

	return session.Save(r, w)
}

func (s *Sessions) getData(r *http.Request) sessionData {
	session, _ := s.store.Get(r, "session")
	data, _ := session.Values["data"].(sessionData)

	return data
}

func randomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64URL(b[:]), nil
}

func s256(verifier string) string {
	data := sha256.Sum256([]byte(verifier))
	return base64URL(data[:])
}

func base64URL(data []byte) string {
	s := base64.URLEncoding.EncodeToString(data[:])
	return strings.TrimRight(s, "=")
}
