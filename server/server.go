package main

import (
	"net/http"

	"strconv"

	"os"

	"bitbucket.org/ThomasWuillemin/easy-sso/server/config"
	"bitbucket.org/ThomasWuillemin/easy-sso/server/sso"
	shared "bitbucket.org/ThomasWuillemin/easy-sso/shared"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

var ssoEngine *sso.SsoEngine
var configFileName string

func main() {

	log.Println("Starting server.")

	// Use the fine given as parameter or the default configuration
	configFileName = "config.json"
	argsWithoutProg := os.Args[1:]
	if len(argsWithoutProg) == 0 {
		log.Error("No configuration file given as parameter. Try to load config.json")
	} else {
		configFileName = argsWithoutProg[0]
	}

	// Load the configuration
	var configuration, err = config.LoadConfiguration(configFileName)
	if err != nil {
		log.Error("Unable to load the configuration.")
		return
	}

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

	// Create the REST server
	engine := gin.Default()

	// If the server is protected, use BasicAuth
	if (configuration.Server.ClientId != nil) && (configuration.Server.ClientPassword != nil) {
		// Create an authorized group with the client id / password
		endpoint := engine.Group(
			"/",
			gin.BasicAuth(
				gin.Accounts{
					*configuration.Server.ClientId: *configuration.Server.ClientPassword}))

		endpoint.GET("/status", handleGetStatus)
		endpoint.GET("/reload-sso-configuration", handleReloadConfiguration)
		endpoint.POST("/token", handleTokenRequest)
		endpoint.POST("/refresh", handleRefreshRequest)

	} else {
		// Otherwise set the endpoint directly on the engine
		engine.GET("/status", handleGetStatus)
		engine.GET("/reload-sso-configuration", handleReloadConfiguration)
		engine.POST("/token", handleTokenRequest)
		engine.POST("/refresh", handleRefreshRequest)
	}

	// Start the application
	if configuration.Server.Port > 0 {
		engine.Run(":" + strconv.Itoa(configuration.Server.Port))
	} else {
		engine.Run()
	}
}

// handleGetStatus returns the status of the server
func handleGetStatus(c *gin.Context) {
	c.String(http.StatusOK, "OK")
}

// handleGetStatus reload the configuration of the SSO
func handleReloadConfiguration(c *gin.Context) {

	// Load the configuration
	configuration, err := config.LoadConfiguration(configFileName)
	if err != nil {
		log.Error("Unable to load the configuration.")
		return
	}

	// Start a new SSO engine and keep track of it
	newSsoEngine, err := sso.NewSsoEngineKeepingRefreshToken(
		configuration.Sso,
		configuration.Ldap,
		configuration.Basic,
		ssoEngine)

	if err != nil {
		c.String(http.StatusInternalServerError, "Unable to reload configuration")
		return
	}
	ssoEngine = newSsoEngine
	c.String(http.StatusOK, "Configuration successfully reloaded")
}

// handleTokenRequest returns (if authorized) a new token associated with the user
// given in a form
func handleTokenRequest(c *gin.Context) {

	var request shared.TokenRequestBody
	c.Bind(&request)

	if len(request.UserName) == 0 {
		c.String(http.StatusBadRequest, "The parameters 'username' was missing")
		return
	}

	if len(request.Password) == 0 {
		c.String(http.StatusBadRequest, "The parameters 'password' was missing")
		return
	}

	// Authenticate the user
	authenticatedUser, err := ssoEngine.Authenticate(request.UserName, request.Password)
	if err != nil {
		if sso.Errors401[err] {
			log.Info("An authentication query was rejected for the user ", request.UserName)
			c.String(http.StatusUnauthorized, "Unauthorized")
		} else {
			c.String(http.StatusInternalServerError, "Unable to serve the request: "+err.Error())
		}
		return
	}

	// Enroll the user
	token, err := ssoEngine.Enroll(authenticatedUser)
	if err != nil {
		if sso.Errors401[err] {
			log.Info("An authentication query was rejected for the user ", request.UserName)
			c.String(http.StatusUnauthorized, "Unauthorized")
		} else {
			c.String(http.StatusInternalServerError, "Unable to serve the request "+err.Error())
		}
		return
	}

	c.JSON(http.StatusOK, token)
}

// handleRefreshRequest returns (if authorized) a new token associated with the refreshToken
// given in a form
func handleRefreshRequest(c *gin.Context) {

	var request shared.TokenRefreshBody
	c.Bind(&request)

	if len(request.RefreshToken) == 0 {
		c.String(http.StatusBadRequest, "The parameters 'refresh_token' was missing")
	}

	// Refresh the token
	token, err := ssoEngine.Refresh(request.RefreshToken)
	if err != nil {
		if sso.Errors401[err] {
			log.Info("An refresh query was rejected for the token ", request.RefreshToken)
			c.String(http.StatusUnauthorized, "Unauthorized")
		} else {
			c.String(http.StatusInternalServerError, "Unable to serve the request "+err.Error())
		}
		return
	}

	c.JSON(http.StatusOK, token)
}
