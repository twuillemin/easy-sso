package server

import (
	"crypto/rsa"
	"time"

	"bitbucket.org/twuillemin/easy-sso-common/pkg/common"
	"github.com/dgrijalva/jwt-go"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

// ssoEngine holds together all the information needed by the default SSO engine
type ssoEngineImpl struct {
	providers            []authenticationProvider
	privateKey           *rsa.PrivateKey
	refreshTokens        map[string]*refreshInformation
	tokenSecondsToLive   int64
	refreshSecondsToLive int64
}

// -------------------------------------------------------------------------------------------
//
// Implementation of interface methods
//
// -------------------------------------------------------------------------------------------

// Authenticate validates the given user/password against all the providers configured in the order give
// by the configuration
func (engine ssoEngineImpl) Authenticate(userName string, password string) (*authenticatedUser, error) {

	for _, provider := range engine.providers {
		if user, err := provider.Authenticate(userName, password); err == nil {
			return user, nil
		}
	}
	return nil, common.ErrUserNotFound
}

// Enroll add the authenticated user in the SSO and returns a new AuthenticatedResponse
func (engine ssoEngineImpl) Enroll(authenticatedUser *authenticatedUser) (*common.AuthenticationResponse, error) {

	return engine.generateAuthenticationResponse(authenticatedUser)
}

// Refresh uses the given refresh token (the id) to returns a new AuthenticatedResponse
func (engine *ssoEngineImpl) Refresh(refreshToken string) (*common.AuthenticationResponse, error) {

	refreshInformation := engine.refreshTokens[refreshToken]

	if refreshInformation == nil {
		log.Error("Unable to find the refreshInformation for the RefreshToken ", refreshToken)
		return nil, common.ErrRefreshTokenNotFound
	}

	if refreshInformation.refreshTimeOut < time.Now().Unix() {
		log.Error("The RefreshToken is too old to be used ", refreshToken)
		return nil, common.ErrRefreshTooOld
	}
	return engine.generateAuthenticationResponse(refreshInformation.authenticatedUser)
}

func (engine ssoEngineImpl) GetRefreshToken() map[string]*refreshInformation {
	return engine.refreshTokens
}

// -------------------------------------------------------------------------------------------
//
// Private methods
//
// -------------------------------------------------------------------------------------------

// generateAuthenticationResponse convert the information from an authentication to a response suitable for the client
func (engine ssoEngineImpl) generateAuthenticationResponse(authenticatedUser *authenticatedUser) (*common.AuthenticationResponse, error) {

	_, token, err := engine.generateJWTToken(authenticatedUser)
	if err != nil {
		log.Error("Unable to generate a response for the authentication/refresh query", err)
		return nil, err
	}

	refreshId := engine.generateRefreshToken(authenticatedUser)

	return &common.AuthenticationResponse{
		TokenType:    "bearer",
		AccessToken:  token,
		RefreshToken: refreshId,
	}, nil
}

// generateRefreshToken generate a new Refresh information for the given user
func (engine ssoEngineImpl) generateRefreshToken(authenticatedUser *authenticatedUser) string {

	refreshUuid := uuid.NewV4()

	refreshId := refreshUuid.String()

	refreshInformation := &refreshInformation{
		authenticatedUser: authenticatedUser,
		refreshTimeOut:    time.Now().Unix() + engine.refreshSecondsToLive,
	}

	engine.refreshTokens[refreshId] = refreshInformation

	return refreshId
}

// generateJWTToken generate a new JWT Token for the given user
func (engine ssoEngineImpl) generateJWTToken(authenticatedUser *authenticatedUser) (*common.CustomClaims, string, error) {

	// Build the claims
	claims := &common.CustomClaims{
		User:  authenticatedUser.UserName,
		Roles: authenticatedUser.Roles,
		StandardClaims: jwt.StandardClaims{
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
