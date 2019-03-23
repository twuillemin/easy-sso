package server

import (
	"net/http"

	log "github.com/sirupsen/logrus"
	"github.com/twuillemin/easy-sso-common/pkg/common"
)

// AddServer creates a new Authentication server and add its endpoint to the given http mux. Note that the endpoints
// are added either to the public mux (e.g.: /token, /refresh) or to the private mux(e.g.: /status, /reload-sso-configuration)
// The same http mux can be used for both public and private
func AddServer(
	configuration *Configuration,
	getCurrentConfiguration func() (*Configuration, error),
	publicServer *http.ServeMux,
	privateServer *http.ServeMux) error {

	// Validate that the configuration was given and is decent
	if err := ValidateConfiguration(configuration); err != nil {
		log.Error("AddServer: Unable to use the configuration for server.")
		return common.ErrBadConfiguration
	}

	if publicServer == nil {
		log.Error("AddServer: parameter publicServer was given null")
		return common.ErrBadConfiguration
	}

	if privateServer == nil {
		log.Error("AddServer : parameter privateServer was given null")
		return common.ErrBadConfiguration
	}

	log.Info("Creating SSO Engine.")

	// Create an Engine
	engine, err := newSsoEngine(configuration)
	if err != nil {
		log.Error("Unable to load the SSO engine.")
		return err
	}

	// Build the function that will reload needed details from the configuration
	reloadConfiguration := func(currentEngine ssoEngine) (ssoEngine, func(request *http.Request) error, error) {

		// Load the new configuration
		configuration, err := getCurrentConfiguration()
		if err != nil {
			log.Error("Unable to load the new SSO engine configuration.")
			return nil, nil, err
		}

		// Create a new Engine
		newEngine, err := newSsoEngineKeepingRefreshToken(configuration, currentEngine)
		if err != nil {
			log.Error("Unable to load the SSO engine.")
			return nil, nil, err
		}

		return newEngine, buildEndpointAuthenticationFunction(*configuration), nil
	}

	// Create a server
	var server authServer = authServerImpl{
		ssoEngine:              engine,
		endpointAuthentication: buildEndpointAuthenticationFunction(*configuration),
		reloadConfiguration:    reloadConfiguration,
	}

	log.Info("Adding SSO Server Handler.")

	// Add the public endpoints
	publicServer.HandleFunc("/token", server.handleTokenRequest)
	publicServer.HandleFunc("/refresh", server.handleRefreshRequest)

	// Add the private endpoints
	privateServer.HandleFunc("/status", server.handleGetStatus)
	privateServer.HandleFunc("/reload-sso-configuration", server.handleReloadConfiguration)

	return nil
}

// checkAuthorization checks if the query can pass the authorization if any defined
func buildEndpointAuthenticationFunction(configuration Configuration) func(request *http.Request) error {

	// If no configuration, skip
	if (configuration.Sso == nil) || (configuration.Sso.ClientId == nil) || (configuration.Sso.ClientPassword == nil) {
		return nil
	}

	return func(request *http.Request) error {
		userName, password, ok := request.BasicAuth()
		if !ok {
			return common.ErrNoAuthorization
		}
		if (userName != *configuration.Sso.ClientId) && (password != *configuration.Sso.ClientPassword) {
			return common.ErrNoAuthorization
		}
		return nil
	}
}
