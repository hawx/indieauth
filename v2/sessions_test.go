package indieauth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"hawx.me/code/assert"
)

func TestSessionsRedirectToSignIn(t *testing.T) {
	assert := assert.Wrap(t)

	me := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<link rel="authorization_endpoint" href="https://auth/" />`)
	}))
	defer me.Close()

	config := &Config{
		ClientID:    "https://example.org/",
		RedirectURL: "https://example.org/redirect",
	}
	sessions, err := NewSessions("KA==", config)
	assert(err).Must.Nil()

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodGet, "/", nil)

	err = sessions.RedirectToSignIn(w, r, me.URL)
	assert(err).Must.Nil()

	resp := w.Result()
	assert(resp.StatusCode).Equal(http.StatusFound)

	sess, _ := sessions.store.Get(r, "session")
	data, ok := sess.Values["data"].(sessionData)
	assert(ok).True()

	expectedRedirect := config.AuthCodeURL(Endpoints{
		Authorization: urlParse("https://auth/"),
	}, data.State, s256(data.Verifier), me.URL)

	assert(resp.Header.Get("Location")).Equal(expectedRedirect)
}

func TestSessionsVerify(t *testing.T) {
	assert := assert.Wrap(t)

	var me *httptest.Server

	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"me": "%s"}`, me.URL)
	}))
	defer auth.Close()

	me = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<link rel="authorization_endpoint" href="%s" />`, auth.URL)
	}))
	defer me.Close()

	config := &Config{
		ClientID:    "https://example.org/",
		RedirectURL: "https://example.org/redirect",
	}
	sessions, err := NewSessions("KA==", config)
	assert(err).Must.Nil()

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader("state=abc&code=1234"))
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	sessions.setData(w, r, sessionData{
		Endpoints: Endpoints{
			Authorization: urlParse(auth.URL),
			Token:         urlParse("http://example.com/token"),
		},
		State:    "abc",
		Verifier: "verified",
	})

	err = sessions.Verify(w, r)
	assert(err).Must.Nil()
}
