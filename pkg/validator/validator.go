package validator

import (
	"io/ioutil"

	"github.com/dgrijalva/jwt-go"
	log "github.com/sirupsen/logrus"
)

// New creates a new Validator with the given configuration. The validator can then be used in the
// queries received to ensure that they are valid
func New(configuration *Configuration) (Validator, error) {

	// Validate the configuration
	if err := ValidateConfiguration(configuration); err != nil {
		log.Error("Unable to use the configuration for validator.")
		return nil, err
	}

	// Read the private key for signing token
	publicKeyData, err := ioutil.ReadFile(*configuration.PublicKeyPath)
	if err != nil {
		log.Error("Configuration for SSO, attribute privateKeyPath is referencing an unreadable file")
		return nil, err
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyData)
	if err != nil {
		log.Error("Configuration for SSO, attribute privateKeyPath is referencing a non-valid file")
		return nil, err
	}

	return &validatorImpl{
		serverPublicKey: publicKey,
	}, nil
}
