/*
Package indieauth authenticates clients using IndieAuth

There are two distinct ways this package can be used: for authentication or for
authorization.

Authentication

The outcome of this flow is a verified URL for the authorizing party. It works
in a couple of steps.

First of all you will need to get the URL to verify, in the example we are using
a parameter "me" for this. From this we can query for the defined authentication
endpoint.

    var session indieauth.Session

    func Handler(w http.ResponseWriter, r *http.Request) {
      meURL, _ := url.Parse(r.FormValue("me"))
      endpoints, _ := indieauth.FindEndpoints(meURL)

      session = indieauth.AuthenticationSession{
        Me:          meURL,
        ClientID:    urlParse("http://client.example.com/"),
        RedirectURI: urlParse("http://client.example.com/callback"),
        State:       "1234",
        Endpoints:   endpoints,
      }

      session.Redirect(w, r)
    }

This will redirect the user to their defined authentication endpoint, which will
on completion redirect to the URL we defined. At that point we will have to
check that the "state" parameter matches what we passed, and then verify the
"code" parameter.

    func Callback(w http.ResponseWriter, r *http.Request) {
      if session.State != r.FormValue("state") {
        http.Error(w, "state does not match", http.StatusBadRequest)
        return
      }

      me, err := session.Verify(r.FormValue("code"))
      if err != nil {
        http.Error(w, "not authorized", http.StatusForbidden)
        return
      }

      fmt.Fprintf(w, "Hello %v\n", me)
    }

You are done!

Authorization

This outcome of this flow is a verified URL and an access token for the
authorizing party. The flow is quite similar.

    var session indieauth.Session

    func Handler(w http.ResponseWriter, r *http.Request) {
      meURL, _ := url.Parse(r.FormValue("me"))
      endpoints, _ := indieauth.FindEndpoints(meURL)

      session = indieauth.AuthorizationSession{
        Me:          meURL,
        ClientID:    urlParse("http://client.example.com/"),
        RedirectURI: urlParse("http://client.example.com/callback"),
        State:       "1234",
        Scopes:      []string{"create"},
        Endpoints:   endpoints,
      }

      session.Redirect(w, r)
    }

The first difference is that we are using RedirectForToken which requires a new
parameter for "scopes". This is a simple non-empty list of strings that will be
presented to the user when authorizing.

    func Callback(w http.ResponseWriter, r *http.Request) {
      if session.State != r.FormValue("state") {
        http.Error(w, "state does not match", http.StatusBadRequest)
        return
      }

      me, err := session.Verify(r.FormValue("code"))
      if err != nil {
        http.Error(w, "not authorized", http.StatusForbidden)
        return
      }

      fmt.Fprintf(w, "Hello %v\n", me)
    }

The second part is again very similar, but we don't finish with

Further Reading

Spec: https://www.w3.org/TR/indieauth/
*/
package indieauth
