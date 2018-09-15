package server

import (
	"bitbucket.org/ThomasWuillemin/easy-sso/pkg/common"
	"crypto/rsa"
	"github.com/dgrijalva/jwt-go"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
)

// newSsoEngine allocates a new ssoEngine with the given configuration
func newSsoEngine(configuration *Configuration) (ssoEngine, error) {

	if configuration == nil {
		log.Error("newSsoEngine : parameter configuration was given null")
		return nil, common.ErrBadConfiguration
	}

	// Build the providers
	ssoProviders, err := newAuthenticationProvider(configuration)
	if err != nil {
		return nil, err
	}

	// The presence of SSO config is checked while loading config
	privateKey, err := loadPrivateKey(*configuration.Sso)
	if err != nil {
		return nil, err
	}

	return &ssoEngineImpl{
		providers:            ssoProviders,
		privateKey:           privateKey,
		refreshTokens:        make(map[string]*refreshInformation),
		tokenSecondsToLive:   *configuration.Sso.TokenSecondsToLive,
		refreshSecondsToLive: *configuration.Sso.RefreshSecondsToLive,
	}, nil
}

// newSsoEngineKeepingRefreshToken allocates a new ssoEngine reusing refresh tokens existing in the previous engine
func newSsoEngineKeepingRefreshToken(configuration *Configuration, previousEngine ssoEngine) (ssoEngine, error) {

	if configuration == nil {
		log.Error("newSsoEngineKeepingRefreshToken : parameter configuration was given null")
		return nil, common.ErrBadConfiguration
	}

	// Build the providers
	ssoProviders, err := newAuthenticationProvider(configuration)
	if err != nil {
		return nil, err
	}

	// The presence of SSO config is checked while loading config
	privateKey, err := loadPrivateKey(*configuration.Sso)
	if err != nil {
		return nil, err
	}

	// Create a new engine, but keep the refresh token
	return &ssoEngineImpl{
		providers:            ssoProviders,
		privateKey:           privateKey,
		refreshTokens:        previousEngine.GetRefreshToken(),
		tokenSecondsToLive:   *configuration.Sso.TokenSecondsToLive,
		refreshSecondsToLive: *configuration.Sso.RefreshSecondsToLive,
	}, nil
}

func loadPrivateKey(configuration SsoConfiguration) (*rsa.PrivateKey, error) {

	// Read the private key for signing token
	privateKeyData, err := ioutil.ReadFile(*configuration.PrivateKeyPath)
	if err != nil {
		log.Error("Configuration for SSO, attribute privateKeyPath is referencing an unreadable file")
		return nil, err
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyData)
	if err != nil {
		log.Error("Configuration for SSO, attribute privateKeyPath is referencing a non-valid file")
		return nil, err
	}

	return privateKey, nil
}
