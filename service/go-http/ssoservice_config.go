package go_http

import (
	"crypto/rsa"
	"errors"
	"github.com/dgrijalva/jwt-go"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"encoding/json"
)

type SsoServiceConfig struct {
	PublicKeyPath *string `json:"publicKeyPath"`
}

var (
	ErrBadConfiguration = errors.New("the configuration of the SSO service is wrong")
)

// readConfiguration reads the configuration and perform various tests ensuring the the configuration is ok
func readConfiguration(configuration *SsoServiceConfig) (*rsa.PublicKey, error) {

	if configuration == nil {
		log.Error("Configuration for Sso is missing")
		return nil, ErrBadConfiguration
	}

	// Basic tests
	if configuration.PublicKeyPath == nil {
		log.Error("Configuration for SSO is missing the definition for publicKeyPath attribute")
		return nil, ErrBadConfiguration
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

	return publicKey, nil
}

// LoadConfiguration loads the configuration file
func LoadConfiguration(file string) (*SsoServiceConfig, error) {

	configFile, err := os.Open(file)
	defer configFile.Close()

	if err != nil {
		return nil, err
	}
	jsonParser := json.NewDecoder(configFile)

	var config SsoServiceConfig
	jsonParser.Decode(&config)

	return &config, nil
}
