package indieauth

import (
	"fmt"
)

type RequestError struct {
	StatusCode int
	MediaType  string
	Body       []byte
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("recieved a %d (%s) response", e.StatusCode, e.MediaType)
}

type clientError int

func (e clientError) Error() string {
	switch e {
	case ErrCannotClaim:
		return "me returned with non-matching authorization endpoint"
	case ErrAuthorizationEndpointMissing:
		return "no authorization endpoint found"
	default:
		panic("missing error definition")
	}
}

const (
	ErrCannotClaim clientError = iota
	ErrAuthorizationEndpointMissing
)
