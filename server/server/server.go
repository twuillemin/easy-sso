package server

import (
	"net/http"

	"strconv"

	"bitbucket.org/ThomasWuillemin/easy-sso/server/config"
	"bitbucket.org/ThomasWuillemin/easy-sso/server/sso"
	shared "bitbucket.org/ThomasWuillemin/easy-sso/shared"
	log "github.com/sirupsen/logrus"
	"errors"
	"fmt"
	"encoding/json"
)

var ssoEngine *sso.SsoEngine
var configFileName string
var configuration *config.Config

var (
	ErrNoAuthorization = errors.New("the query does not have a valid Authorization")
)

func StartServer(configurationFileName string) {

	// Keep the configuration file name
	configFileName = configurationFileName

	// Load the configuration
	conf, err := config.LoadConfiguration(configFileName)
	if err != nil {
		log.Error("Unable to load the configuration.")
		return
	}
	configuration = conf

	log.Println("Starting server.")

	// Start the SSO engine and keep track of it
	newSsoEngine, err := sso.NewSsoEngine(
		configuration.Sso,
		configuration.Ldap,
		configuration.Basic)
	if err != nil {
		log.Error("Unable to load the SSO engine.")
		return
	}
	ssoEngine = newSsoEngine

	http.HandleFunc("/status", handleGetStatus)
	http.HandleFunc("/reload-sso-configuration", handleReloadConfiguration)
	http.HandleFunc("/token", handleTokenRequest)
	http.HandleFunc("/refresh", handleRefreshRequest)

	// Create the REST server
	if (configuration.Server.HttpsCertificate != nil) && (configuration.Server.HttpsCertificateKey != nil) {
		http.ListenAndServeTLS(
			":"+strconv.Itoa(configuration.Server.Port),
			*configuration.Server.HttpsCertificate,
			*configuration.Server.HttpsCertificateKey,
			nil)
	} else {
		http.ListenAndServe(":"+strconv.Itoa(configuration.Server.Port), nil)
	}
}

// handleGetStatus returns the status of the server
func handleGetStatus(writer http.ResponseWriter, request *http.Request) {

	if err := checkAuthorization(writer, request); err != nil {
		return
	}

	writer.Header().Set("Content-Type", "text/plain")
	writer.WriteHeader(http.StatusOK)
	fmt.Fprint(writer, "OK")
}

// handleGetStatus reload the configuration of the SSO
func handleReloadConfiguration(writer http.ResponseWriter, request *http.Request) {

	if err := checkAuthorization(writer, request); err != nil {
		return
	}

	// Load the configuration
	configuration, err := config.LoadConfiguration(configFileName)
	if err != nil {
		log.Error("Unable to load the configuration - error reading from the file")
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(writer, "Unable to load the configuration")
		return
	}

	// Start a new SSO engine and keep track of it
	newSsoEngine, err := sso.NewSsoEngineKeepingRefreshToken(
		configuration.Sso,
		configuration.Ldap,
		configuration.Basic,
		ssoEngine)

	if err != nil {
		log.Error("Unable to load the configuration - error creating a new SSO engine instance")
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(writer, "Unable to load the configuration")
		return
	}
	ssoEngine = newSsoEngine
	writer.Header().Set("Content-Type", "text/plain")
	writer.WriteHeader(http.StatusOK)
	fmt.Fprint(writer, "OK")
}

// handleTokenRequest returns (if authorized) a new token associated with the user
// given in a form
func handleTokenRequest(writer http.ResponseWriter, request *http.Request) {

	if err := checkAuthorization(writer, request); err != nil {
		return
	}

	// Read the parameters of the request
	decoder := json.NewDecoder(request.Body)
	var tokenRequest shared.TokenRequestBody
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
	authenticatedUser, err := ssoEngine.Authenticate(tokenRequest.UserName, tokenRequest.Password)
	if err != nil {
		if sso.Errors401[err] {
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
	token, err := ssoEngine.Enroll(authenticatedUser)
	if err != nil {
		if sso.Errors401[err] {
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
func handleRefreshRequest(writer http.ResponseWriter, request *http.Request) {

	if err := checkAuthorization(writer, request); err != nil {
		return
	}

	// Read the parameters of the request
	decoder := json.NewDecoder(request.Body)
	var refreshRequest shared.TokenRefreshBody
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
	token, err := ssoEngine.Refresh(refreshRequest.RefreshToken)
	if err != nil {
		if sso.Errors401[err] {
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

// checkAuthorization checks if the query can pass the authorization if any defined
func checkAuthorization(writer http.ResponseWriter, request *http.Request) error {

	// If no configuration, skip
	if (configuration.Server.ClientId == nil) || (configuration.Server.ClientPassword == nil) {
		return nil
	}
	// Get the Authorization from the query
	userName, password, ok := request.BasicAuth()
	if !ok {
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
		return ErrNoAuthorization
	}
	if (userName != *configuration.Server.ClientId) && (password != *configuration.Server.ClientPassword) {
		http.Error(writer, "Unauthorized", http.StatusUnauthorized)
		return ErrNoAuthorization
	}
	return nil
}
