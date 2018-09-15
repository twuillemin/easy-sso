package connector

import (
	"bitbucket.org/ThomasWuillemin/easy-sso/pkg/common"
	log "github.com/sirupsen/logrus"
)

type AuthConnectorConfig struct {
	ServerBaseURL                *string `json:"serverBaseURL"`
	ServerPublicHTTPSCertificate *string `json:"serverPublicHTTPSCertificate"`
	ServerClientId               *string `json:"clientId"`
	ServerClientPassword         *string `json:"clientPassword"`
}

// ValidateConfiguration validates the configuration data
func ValidateConfiguration(configuration *AuthConnectorConfig) error {

	if configuration == nil {
		log.Error("Configuration for connector is missing")
		return common.ErrBadConfiguration
	}

	// Basic tests
	if configuration.ServerBaseURL == nil {
		log.Error("Configuration for SSO Client is missing the definition for serverBaseURL")
		return common.ErrBadConfiguration
	}

	if ((configuration.ServerClientId == nil) && (configuration.ServerClientPassword != nil)) ||
		((configuration.ServerClientId != nil) && (configuration.ServerClientPassword == nil)) {
		log.Error("Configuration for SSO Client is having a mismatch for the attributes clientId and clientPassword")
		return common.ErrBadConfiguration
	}
	return nil
}
