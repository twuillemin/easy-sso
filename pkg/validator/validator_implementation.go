package validator

import (
	"crypto/rsa"
	"github.com/twuillemin/easy-sso-common/pkg/common"
	"net/http"
)

type validatorImpl struct {
	serverPublicKey *rsa.PublicKey
}

// GetUserFromTokenOrFail is be inserted at beginning of each endpoint for ensuring that
// the authentication token is present and valid
func (validator validatorImpl) GetUserFromHeaderOrFail(writer http.ResponseWriter, request *http.Request) (string, []string, error) {

	// Use the common package to retrieve authentication
	authenticationInformation, err := common.GetAuthenticationFromRequest(request, validator.serverPublicKey, false)
	if err != nil {
		switch err {
		case common.ErrMalformedAuthorization:
		case common.ErrTokenMalformed:
			{
				// Write an error and stop the handler chain
				http.Error(writer, "Bad Request", http.StatusBadRequest)
			}
		case common.ErrSignatureInvalid:
		case common.ErrNoAuthorization:
			{
				http.Error(writer, "Unauthorized", http.StatusUnauthorized)
			}
		default:
			{
				http.Error(writer, "Internal Server Error", http.StatusInternalServerError)
			}
		}
		return "", nil, err
	}

	return authenticationInformation.User, authenticationInformation.Roles, nil
}
