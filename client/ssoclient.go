package client

import (
	shared "bitbucket.org/ThomasWuillemin/easy-sso/shared"
	"bitbucket.org/ThomasWuillemin/easy-sso/client/httpconnector"
	"net/http"
	"fmt"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"time"
)

type SsoClient struct {
	connector      Connector
	authentication shared.AuthenticationResponse
	expireAt       int64
}

var (
	ErrMalformedToken = errors.New("the token is not readable")
)

// NewSsoClient allocates a new SsoClient with the given configuration
func NewSsoClient(configuration *httpconnector.HttpConnectorConfig, userName string, password string) (*SsoClient, error) {

	// Create a new connector with the given configuration
	connector, err := httpconnector.NewHttpConnector(configuration)
	if err != nil {
		return nil, err
	}

	// Use the connector to connect
	authentication, err := connector.RequestToken(userName, password)
	if err != nil {
		return nil, err
	}

	expireAt, err := getExpirationFromToken(authentication.AccessToken)
	if err != nil {
		return nil, err
	}

	return &SsoClient{
		connector:      *connector,
		authentication: *authentication,
		expireAt:       expireAt,
	}, nil
}

// AuthenticateRequest adds the Authorization bearer information to the given query.
func (client *SsoClient) AuthenticateRequest(request *http.Request) error {

	// If the token is expired (with a 5 seconds margin)
	if client.expireAt > (time.Now().Unix() - 5) {
		// Request a new token
		authentication, err := client.connector.RequestRefresh(client.authentication.RefreshToken)
		if err != nil {
			return err
		}
		expireAt, err := getExpirationFromToken((*authentication).AccessToken)
		if err != nil {
			return err
		}
		// Update the token
		client.authentication = *authentication
		client.expireAt = expireAt
	}

	// Add the information to the query
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", client.authentication.AccessToken))
	return nil
}

// AuthenticateRequest adds the Authorization bearer information to the given query.
func getExpirationFromToken(accessToken string) (int64, error) {

	// Read the token without validating it
	token, _, err := new(jwt.Parser).ParseUnverified(accessToken, &shared.CustomClaims{})
	if err != nil {
		return 0, ErrMalformedToken
	}

	// Read the claims
	claims, ok := token.Claims.(*shared.CustomClaims) // claims.User and claims.Roles are what we are interested in.
	if !ok {
		return 0, ErrMalformedToken
	}

	return claims.ExpiresAt, nil
}
