package connector

import (
	"fmt"
	"net/http"
	"time"

	"github.com/twuillemin/easy-sso-common/pkg/common"
)

type clientImpl struct {
	connector      Connector
	authentication common.AuthenticationResponse
	expireAt       int64
}

// AuthenticateRequest adds the Authorization bearer information to the given query.
func (client clientImpl) AuthenticateRequest(request *http.Request) error {

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
