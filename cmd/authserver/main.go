package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"

	"bitbucket.org/twuillemin/easy-sso-common/pkg/common"
	"bitbucket.org/twuillemin/easy-sso/pkg/server"
	log "github.com/sirupsen/logrus"
)

func main() {

	// Use the fine given as parameter or the default configuration
	configFileNameToUse := "config.json"
	argsWithoutProgramName := os.Args[1:]
	if len(argsWithoutProgramName) == 0 {
		log.Warn("No configuration file given as parameter. Try to load config.json")
	} else {
		configFileNameToUse = argsWithoutProgramName[0]
	}

	// Load the configuration
	configuration, err := loadAppConfiguration(configFileNameToUse)
	if err != nil {
		log.Error("Unable to load configuration.")
		return
	}

	// Create the http mux that will host the authServer
	mixedHTTPServer := http.NewServeMux()

	// Create the authServer
	server.AddServer(
		configuration.AuthServerConfig,
		func() (*server.Configuration, error) {
			fullConfig, err := loadAppConfiguration(configFileNameToUse)
			if err != nil {
				return nil, err
			}
			return fullConfig.AuthServerConfig, nil
		},
		mixedHTTPServer,
		mixedHTTPServer)

	// Create the REST server
	if (configuration.Server.HttpsCertificate != nil) && (configuration.Server.HttpsCertificateKey != nil) {
		http.ListenAndServeTLS(
			":"+strconv.Itoa(configuration.Server.Port),
			*configuration.Server.HttpsCertificate,
			*configuration.Server.HttpsCertificateKey,
			mixedHTTPServer)
	} else {
		http.ListenAndServe(":"+strconv.Itoa(configuration.Server.Port), mixedHTTPServer)
	}
}

type Config struct {
	Server           *ServerConfig         `json:"server"`
	AuthServerConfig *server.Configuration `json:"server"`
}

type ServerConfig struct {
	Port                int     `json:"port"`
	HttpsCertificate    *string `json:"httpsCertificate"`
	HttpsCertificateKey *string `json:"httpsCertificateKey"`
}

// loadAppConfiguration loads the configuration file
func loadAppConfiguration(file string) (*Config, error) {

	// Try to open the file
	configFile, err := os.Open(file)
	defer configFile.Close()

	if err != nil {
		return nil, err
	}
	jsonParser := json.NewDecoder(configFile)

	// Read the JSON
	var configuration Config
	jsonParser.Decode(&configuration)

	if configuration.Server == nil {
		log.Error("Configuration for the server is missing")
		return nil, common.ErrBadConfiguration
	}

	if configuration.AuthServerConfig == nil {
		log.Error("Configuration for the server is missing")
		return nil, common.ErrBadConfiguration
	}

	if configuration.Server.Port < 0 || configuration.Server.Port > 65535 {
		log.Error("Configuration for the server port must have a value between 0 and 65535")
		return nil, common.ErrBadConfiguration
	}

	err = server.ValidateConfiguration(configuration.AuthServerConfig)
	if err != nil {
		log.Error("Unable to use the configuration.")
		return nil, common.ErrBadConfiguration
	}

	return &configuration, nil
}
