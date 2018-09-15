package server

import "net/http"

// authServer defines all the function needed for an authentication server. All the functions are defined
// as http handler, so that the server can be added easily to an existing application
type authServer interface {

	// handleGetStatus returns the status of the server
	HandleGetStatus(writer http.ResponseWriter, request *http.Request)

	// handleGetStatus reload the configuration of the SSO
	HandleReloadConfiguration(writer http.ResponseWriter, request *http.Request)

	// handleTokenRequest returns (if authorized) a new token associated with the user
	// given in a form
	HandleTokenRequest(writer http.ResponseWriter, request *http.Request)

	// handleRefreshRequest returns (if authorized) a new token associated with the refreshToken
	// given in a form
	HandleRefreshRequest(writer http.ResponseWriter, request *http.Request)
}
