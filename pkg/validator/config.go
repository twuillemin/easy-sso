package validator

import (
	log "github.com/sirupsen/logrus"
	"github.com/twuillemin/easy-sso-common/pkg/common"
)

type Configuration struct {
	PublicKeyPath *string `json:"publicKeyPath"`
}

// validateConfiguration validates the configuration data
func ValidateConfiguration(configuration *Configuration) error {

	if configuration == nil {
		log.Error("Configuration for authvalidator is missing")
		return common.ErrBadConfiguration
	}

	// Basic tests
	if configuration.PublicKeyPath == nil {
		log.Error("Configuration for SSO is missing the definition for publicKeyPath attribute")
		return common.ErrBadConfiguration
	}

	return nil
}
