package go_http

import (
	"errors"
	log "github.com/sirupsen/logrus"
)

type SsoClientConfig struct {
	ServerBaseURL        *string `json:"serverBaseURL"`
	ServerClientId       *string `json:"clientId"`
	ServerClientPassword *string `json:"clientPassword"`
}

var (
	ErrBadConfiguration = errors.New("the configuration of the SSO service is wrong")
)

// readConfiguration reads the configuration and perform various tests ensuring the the configuration is ok
func readConfiguration(configuration *SsoClientConfig) (error) {

	if configuration == nil {
		log.Error("Configuration for SSO Client is missing")
		return ErrBadConfiguration
	}

	// Basic tests
	if configuration.ServerBaseURL == nil {
		log.Error("Configuration for SSO Client is missing the definition for serverBaseURL")
		return ErrBadConfiguration
	}
	if ((configuration.ServerClientId == nil) && (configuration.ServerClientPassword != nil)) ||
		((configuration.ServerClientId != nil) && (configuration.ServerClientPassword == nil)) {
		log.Error("Configuration for SSO Client is having a mismatch for the attributes clientId and clientPassword")
		return ErrBadConfiguration
	}
	return nil
}


