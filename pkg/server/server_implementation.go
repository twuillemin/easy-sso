package server

import (
	"bitbucket.org/ThomasWuillemin/easy-sso/pkg/common"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net/http"
)

// errors401 is a map holding the various errors that should (but not must) generate a 401 error in the general context
var errors401 = map[error]bool{
	common.ErrRefreshTokenNotFound: true,
	common.ErrUnauthorized:         true,
	common.ErrUserNotFound:         true,
}

type authServerImpl struct {
	// The SSO engine by itself
	ssoEngine ssoEngine
	// The optional function protecting the endpoints
	endpointAuthentication func(request *http.Request) error
	// The function for updating the configuration
	reloadConfiguration func(currentEngine ssoEngine) (ssoEngine, func(request *http.Request) error, error)
}

// handleGetStatus returns the status of the server
func (server authServerImpl) HandleGetStatus(writer http.ResponseWriter, request *http.Request) {

	// Check endpoint Authentication
	if err := checkEndPointAuthentication(server.endpointAuthentication, request, writer); err != nil {
		return
	}

	writer.Header().Set("Content-Type", "text/plain")
	writer.WriteHeader(http.StatusOK)
	fmt.Fprint(writer, "OK")
}

// handleGetStatus reload the configuration of the SSO
func (server authServerImpl) HandleReloadConfiguration(writer http.ResponseWriter, request *http.Request) {

	// Check endpoint Authentication
	if err := checkEndPointAuthentication(server.endpointAuthentication, request, writer); err != nil {
		return
	}

	if server.reloadConfiguration == nil {
		log.Error("Unable to reload the configuration - no reload function was given")
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(writer, "Unable to reload the configuration")
		return
	}

	// Grab a new ssoEngine and an authentication function
	newSsoEngine, newAuthenticationFunction, err := server.reloadConfiguration(server.ssoEngine)
	if err != nil {
		log.Error("Unable to load the configuration - error creating a new SSO engine instance")
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(writer, "Unable to reload the configuration")
		return
	}

	server.ssoEngine = newSsoEngine
	server.endpointAuthentication = newAuthenticationFunction
	writer.Header().Set("Content-Type", "text/plain")
	writer.WriteHeader(http.StatusOK)
	fmt.Fprint(writer, "OK")
}

// handleTokenRequest returns (if authorized) a new token associated with the user
// given in a form
func (server authServerImpl) HandleTokenRequest(writer http.ResponseWriter, request *http.Request) {

	// Check endpoint Authentication
	if err := checkEndPointAuthentication(server.endpointAuthentication, request, writer); err != nil {
		return
	}

	// Read the parameters of the request
	decoder := json.NewDecoder(request.Body)
	var tokenRequest common.TokenRequestBody
	err := decoder.Decode(&tokenRequest)
	if err != nil {
		log.Debug("Unable to read the request")
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(writer, "Unable to read the request")
		return
	}

	// Close the body
	defer request.Body.Close()

	if len(tokenRequest.UserName) == 0 {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(writer, "The parameters 'userName' was missing in the query")
		return
	}

	if len(tokenRequest.Password) == 0 {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(writer, "The parameters 'password' was missing in the query")
		return
	}

	// Authenticate the user
	authenticatedUser, err := server.ssoEngine.Authenticate(tokenRequest.UserName, tokenRequest.Password)
	if err != nil {
		if errors401[err] {
			writer.Header().Set("Content-Type", "text/plain")
			writer.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(writer, "Unauthorized")
		} else {
			writer.Header().Set("Content-Type", "text/plain")
			writer.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(writer, "Unable to serve the request")
		}
		return
	}

	// Enroll the user
	token, err := server.ssoEngine.Enroll(authenticatedUser)
	if err != nil {
		if errors401[err] {
			writer.Header().Set("Content-Type", "text/plain")
			writer.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(writer, "Unauthorized")
		} else {
			writer.Header().Set("Content-Type", "text/plain")
			writer.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(writer, "Unable to serve the request")
		}
		return
	}

	// Prepare the response
	jsonResponse, err := json.Marshal(token)
	if err != nil {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(writer, "Unable to serve the request")
	}

	// Send the response back
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	writer.Write(jsonResponse)
}

// handleRefreshRequest returns (if authorized) a new token associated with the refreshToken
// given in a form
func (server authServerImpl) HandleRefreshRequest(writer http.ResponseWriter, request *http.Request) {

	// Check endpoint Authentication
	if err := checkEndPointAuthentication(server.endpointAuthentication, request, writer); err != nil {
		return
	}

	// Read the parameters of the request
	decoder := json.NewDecoder(request.Body)
	var refreshRequest common.TokenRefreshBody
	err := decoder.Decode(&refreshRequest)
	if err != nil {
		log.Debug("Unable to read the request")
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(writer, "Unable to read the request")
		return
	}

	// Close the body
	defer request.Body.Close()

	if len(refreshRequest.RefreshToken) == 0 {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(writer, "The parameters 'refreshToken' was missing in the query")
		return
	}

	// Refresh the token
	token, err := server.ssoEngine.Refresh(refreshRequest.RefreshToken)
	if err != nil {
		if errors401[err] {
			writer.Header().Set("Content-Type", "text/plain")
			writer.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(writer, "Unauthorized")
		} else {
			writer.Header().Set("Content-Type", "text/plain")
			writer.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(writer, "Unable to serve the request")
		}
		return
	}

	// Prepare the response
	jsonResponse, err := json.Marshal(token)
	if err != nil {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(writer, "Unable to serve the request")
	}

	// Send the response back
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	writer.Write(jsonResponse)
}

// checkEndPointAuthentication checks if the query can pass the authorization if any defined
func checkEndPointAuthentication(
	checkAuthentication func(request *http.Request) error,
	request *http.Request,
	writer http.ResponseWriter) error {

	if checkAuthentication == nil {
		return nil
	}

	if err := checkAuthentication(request); err != nil {
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
		return common.ErrNoAuthorization
	}

	return nil
}
