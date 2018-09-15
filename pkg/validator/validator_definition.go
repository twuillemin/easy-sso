package validator

import "net/http"

type Validator interface {
	// GetUserFromTokenOrFail is be inserted at beginning of each endpoint for ensuring that
	// the authentication token is present and valid
	GetUserFromHeaderOrFail(writer http.ResponseWriter, request *http.Request) (string, []string, error)
}
