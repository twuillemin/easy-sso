package sso

import (
	"crypto/rsa"
	"errors"
	"time"

	"bitbucket.org/ThomasWuillemin/easy-sso/server/providers"
	shared "bitbucket.org/ThomasWuillemin/easy-sso/shared"
	"github.com/dgrijalva/jwt-go"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

var (
	ErrRefreshTokenNotFound = errors.New("the requested RefreshToken is not known")
	ErrRefreshTooOld        = errors.New("the requested RefreshToken is too old")
	ErrBadConfiguration     = errors.New("the configuration of the server is wrong")
)

// Errors401 is a map holding the various errors that should (but not must) generate a 401 error in the general context
var Errors401 = map[error]bool{
	ErrRefreshTokenNotFound:   true,
	providers.ErrUnauthorized: true,
	providers.ErrUserNotFound: true,
}

// RefreshInformation holds the information needed to re-issue a token when a refresh is asked
type RefreshInformation struct {
	authenticatedUser *providers.AuthenticatedUser
	refreshTimeOut    int64
}

// SsoEngine holds together all the information needed by the SSO engine
type SsoEngine struct {
	providers            []providers.AuthenticationProvider
	privateKey           *rsa.PrivateKey
	refreshTokens        map[string]*RefreshInformation
	tokenSecondsToLive   int64
	refreshSecondsToLive int64
}

// CustomClaims holds together all the claims that will be present in the JWT Token
type CustomClaims struct {
	User  string   `json:"user"`
	Roles []string `json:"roles"`
	jwt.StandardClaims
}

// NewSsoEngine allocates a new SsoEngine with the given configuration
func NewSsoEngine(
	configuration *SsoConfig,
	ldapProviderConfig *providers.LdapProviderConfig,
	basicProviderConfig *providers.BasicProviderConfig) (*SsoEngine, error) {

	privateKey, ssoProviders, err := readConfiguration(configuration, ldapProviderConfig, basicProviderConfig)
	if err != nil {
		return nil, err
	}

	return &SsoEngine{
		providers:            ssoProviders,
		privateKey:           privateKey,
		refreshTokens:        make(map[string]*RefreshInformation),
		tokenSecondsToLive:   *configuration.TokenSecondsToLive,
		refreshSecondsToLive: *configuration.RefreshSecondsToLive,
	}, nil
}

// NewSsoEngine allocates a new SsoEngine reusing refresh tokens existing in the previous engine
func NewSsoEngineKeepingRefreshToken(
	configuration *SsoConfig,
	ldapProviderConfig *providers.LdapProviderConfig,
	basicProviderConfig *providers.BasicProviderConfig,
	previousEngine *SsoEngine) (*SsoEngine, error) {

	privateKey, ssoProviders, err := readConfiguration(configuration, ldapProviderConfig, basicProviderConfig)
	if err != nil {
		return nil, err
	}

	return &SsoEngine{
		providers:            ssoProviders,
		privateKey:           privateKey,
		refreshTokens:        previousEngine.refreshTokens,
		tokenSecondsToLive:   *configuration.TokenSecondsToLive,
		refreshSecondsToLive: *configuration.RefreshSecondsToLive,
	}, nil
}

// Authenticate validates the given user/password against all the providers configured in the order give
// by the configuration
func (engine *SsoEngine) Authenticate(userName string, password string) (*providers.AuthenticatedUser, error) {

	for _, provider := range engine.providers {
		if user, err := provider.Authenticate(userName, password); err == nil {
			return user, nil
		}
	}
	return nil, providers.ErrUserNotFound
}

// Enroll add the authenticated user in the SSO and returns a new AuthenticatedResponse
func (engine *SsoEngine) Enroll(authenticatedUser *providers.AuthenticatedUser) (*shared.AuthenticationResponse, error) {

	return engine.generateAuthenticationResponse(authenticatedUser)
}

// Refresh uses the given refresh token (the id) to returns a new AuthenticatedResponse
func (engine *SsoEngine) Refresh(refreshToken string) (*shared.AuthenticationResponse, error) {

	refreshInformation := engine.refreshTokens[refreshToken]

	if refreshInformation == nil {
		log.Error("Unable to find the refreshInformation for the RefreshToken ", refreshToken)
		return nil, ErrRefreshTokenNotFound
	}

	if refreshInformation.refreshTimeOut < time.Now().Unix() {
		log.Error("The RefreshToken is too old to be used ", refreshToken)
		return nil, ErrRefreshTooOld
	}
	return engine.generateAuthenticationResponse(refreshInformation.authenticatedUser)
}

// generateAuthenticationResponse convert the information from an authentication to a response suitable for the client
func (engine *SsoEngine) generateAuthenticationResponse(authenticatedUser *providers.AuthenticatedUser) (*shared.AuthenticationResponse, error) {

	_, token, err := engine.generateJWTToken(authenticatedUser)
	if err != nil {
		log.Error("Unable to generate a response for the authentication/refresh query", err)
		return nil, err
	}

	refreshId, err := engine.generateRefreshToken(authenticatedUser)
	if err != nil {
		log.Error("Unable to generate a response for the authentication/refresh query", err)
		return nil, err
	}

	return &shared.AuthenticationResponse{
		TokenType:    "bearer",
		AccessToken:  token,
		RefreshToken: refreshId,
	}, nil
}

// generateRefreshToken generate a new Refresh information for the given user
func (engine *SsoEngine) generateRefreshToken(authenticatedUser *providers.AuthenticatedUser) (string, error) {

	refreshUuid := uuid.NewV4()

	refreshId := refreshUuid.String()

	refreshInformation := &RefreshInformation{
		authenticatedUser: authenticatedUser,
		refreshTimeOut:    time.Now().Unix() + engine.refreshSecondsToLive,
	}

	engine.refreshTokens[refreshId] = refreshInformation

	return refreshId, nil
}

// generateJWTToken generate a new JWT Token for the given user
func (engine SsoEngine) generateJWTToken(authenticatedUser *providers.AuthenticatedUser) (*CustomClaims, string, error) {

	// Build the claims
	claims := &CustomClaims{
		authenticatedUser.UserName,
		authenticatedUser.Roles,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Unix() + engine.tokenSecondsToLive,
			Issuer:    "Easy SSO Server",
		},
	}
	// Build the token
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)

	// Convert the token to a string
	tokenString, err := token.SignedString(engine.privateKey)
	if err != nil {
		log.Error("Unable to sign generated token", err)
		return nil, "", err
	}
	return claims, tokenString, nil
}
