package sso

import (
	"crypto/rsa"
	"io/ioutil"
	"os"

	"bitbucket.org/ThomasWuillemin/easy-sso/server/providers"
	"github.com/dgrijalva/jwt-go"
	log "github.com/sirupsen/logrus"
)

// SsoConfig defines the configuration parameters of the SSO engine
type SsoConfig struct {
	PrivateKeyPath       *string    `json:"privateKeyPath"`
	TokenSecondsToLive   *int64     `json:"tokenSecondsToLive"`
	RefreshSecondsToLive *int64     `json:"refreshSecondsToLive"`
	Providers            *[]*string `json:"providers"`
}

// readConfiguration reads the configuration and perform various tests ensuring the the configuration is ok
func readConfiguration(
	configuration *SsoConfig,
	ldapProviderConfig *providers.LdapProviderConfig,
	basicProviderConfig *providers.BasicProviderConfig) (*rsa.PrivateKey, []providers.AuthenticationProvider, error) {

	if configuration == nil {
		log.Error("Configuration for Sso is missing")
		return nil, nil, ErrBadConfiguration
	}

	// Basic tests
	if configuration.PrivateKeyPath == nil {
		log.Error("Configuration for SSO is missing the definition for privateKeyPath attribute")
		return nil, nil, ErrBadConfiguration
	}
	if configuration.TokenSecondsToLive == nil {
		log.Error("Configuration for SSO is missing the definition for tokenSecondsToLive attribute")
		return nil, nil, ErrBadConfiguration
	}
	if configuration.RefreshSecondsToLive == nil {
		log.Error("Configuration for SSO is missing the definition for refreshSecondsToLive attribute")
		return nil, nil, ErrBadConfiguration
	}
	if configuration.Providers == nil || len(*configuration.Providers) == 0 {
		log.Error("Configuration for SSO is missing the definition for providers attribute")
		return nil, nil, ErrBadConfiguration
	}
	if len(*configuration.Providers) > 2 {
		log.Error("Configuration for SSO, attribute providers is limited to two entries")
		return nil, nil, ErrBadConfiguration
	}
	if len(*configuration.Providers) == 2 {
		// Just in case we have someone having fun
		if *(*configuration.Providers)[0] == *(*configuration.Providers)[1] {
			log.Error("Configuration for SSO, attribute providers must specify different provider for each entry")
			return nil, nil, ErrBadConfiguration
		}
	}

	// More advanced test
	if _, err := os.Stat(*configuration.PrivateKeyPath); os.IsNotExist(err) {
		log.Error("Configuration for SSO, attribute tokenCertificate is referencing a not existing file")
		return nil, nil, ErrBadConfiguration
	}
	if *configuration.TokenSecondsToLive < 0 {
		log.Error("Configuration for SSO, attribute tokenSecondsToLive can not be less than 0")
		return nil, nil, ErrBadConfiguration
	}
	if *configuration.RefreshSecondsToLive < 0 {
		log.Error("Configuration for SSO, attribute refreshSecondsToLive can not be less than 0")
		return nil, nil, ErrBadConfiguration
	}
	if *configuration.RefreshSecondsToLive <= *configuration.TokenSecondsToLive {
		log.Error("Configuration for SSO, attribute refreshSecondsToLive can not be less than tokenSecondsToLive")
		return nil, nil, ErrBadConfiguration
	}

	// Try to build the providers
	ssoProviders := make([]providers.AuthenticationProvider, 0, len(*configuration.Providers))
	for _, providerName := range *configuration.Providers {
		if *providerName == "basic" {

			// Create a new Basic Provider
			basicProvider, err := providers.NewBasicProvider(basicProviderConfig)
			if err != nil {
				log.Error("Configuration for SSO, attribute providers is set to use the \"basic\" provider, but this provider can not be configured")
				return nil, nil, ErrBadConfiguration
			}

			// Add it the list of providers
			ssoProviders = append(ssoProviders, basicProvider)

		} else if *providerName == "ldap" {

			// Create a new Basic Provider
			ldapProvider, err := providers.NewLdapProvider(ldapProviderConfig)
			if err != nil {
				log.Error("Configuration for SSO, attribute providers is set to use the \"ldap\" provider, but this provider can not be configured")
				return nil, nil, ErrBadConfiguration
			}

			// Add it the list of providers
			ssoProviders = append(ssoProviders, ldapProvider)

		} else {
			log.Error("Configuration for SSO, attribute providers can only be \"basic\" or \"ldap\"")
			return nil, nil, ErrBadConfiguration
		}
	}

	// Read the private key for signing token
	privateKeyData, err := ioutil.ReadFile(*configuration.PrivateKeyPath)
	if err != nil {
		log.Error("Configuration for SSO, attribute privateKeyPath is referencing an unreadable file")
		return nil, nil, err
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyData)
	if err != nil {
		log.Error("Configuration for SSO, attribute privateKeyPath is referencing a non-valid file")
		return nil, nil, err
	}

	return privateKey, ssoProviders, nil
}
