package indieauth

type Response struct {
	AccessToken string
	TokenType   string
	Scopes      []string
	Me          string
	Profile     map[string]interface{}
}

// HasScope returns true if the Response was issued with the scope.
func (r Response) HasScope(scope string) bool {
	for _, candidate := range r.Scopes {
		if candidate == scope {
			return true
		}
	}

	return false
}
