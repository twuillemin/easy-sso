package connector

import (
	"bitbucket.org/twuillemin/easy-sso/pkg/common"
)

// Connector is a generic interface for connecting to the SSO server. Currently only the HTTP
// connector is implemented
type Connector interface {
	// RequestToken requests a new Token from the SSO server
	RequestToken(userName string, password string) (*common.AuthenticationResponse, error)
	// RequestRefresh requests a refreshed Token from the SSO server
	RequestRefresh(refreshToken string) (*common.AuthenticationResponse, error)
}
