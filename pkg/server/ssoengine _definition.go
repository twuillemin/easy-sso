package server

import (
	"bitbucket.org/twuillemin/easy-sso/pkg/common"
)

// ssoEngine defines all the function needed for a SSO engine
type ssoEngine interface {
	// Authenticate validates the given user/password against all the providers configured in the order give
	// by the configuration
	Authenticate(userName string, password string) (*authenticatedUser, error)
	// Enroll add the authenticated user in the SSO and returns a new AuthenticatedResponse
	Enroll(authenticatedUser *authenticatedUser) (*common.AuthenticationResponse, error)
	// Refresh uses the given refresh token (the id) to returns a new AuthenticatedResponse
	Refresh(refreshToken string) (*common.AuthenticationResponse, error)
	// Return the list of current active refresh tokens, so that another engine can be
	// created without loosing the history
	GetRefreshToken() map[string]*refreshInformation
}

// refreshInformation holds the information needed to re-issue a token when a refresh is asked
type refreshInformation struct {
	authenticatedUser *authenticatedUser
	refreshTimeOut    int64
}
