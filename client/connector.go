package client

import (
	shared "bitbucket.org/ThomasWuillemin/easy-sso/shared"
)

// Connector is a generic interface for connecting to the SSO server. Currently only the HTTP
// connector is implemented
type Connector interface {
	RequestToken(userName string, password string) (*shared.AuthenticationResponse, error)
	RequestRefresh(refreshToken string) (*shared.AuthenticationResponse, error)
}
