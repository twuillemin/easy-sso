package validator

import (
	"bitbucket.org/twuillemin/easy-sso/pkg/common"
	"crypto/rsa"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"strings"
	"time"
)

type validatorImpl struct {
	serverPublicKey *rsa.PublicKey
}

// GetUserFromTokenOrFail is be inserted at beginning of each endpoint for ensuring that
// the authentication token is present and valid
func (validator validatorImpl) GetUserFromHeaderOrFail(writer http.ResponseWriter, request *http.Request) (string, []string, error) {
	authorization := request.Header.Get("Authorization")

	// If no authorization (8 is the minimum for Bearer + 1 char token)
	if len(authorization) == 0 {
		http.Error(writer, "No valid Authorization header", http.StatusUnauthorized)
		return "", nil, common.ErrNoAuthorization
	}

	// If no authorization (8 is the minimum for Bearer + 1 char token)
	if len(authorization) < 8 {
		http.Error(writer, "Malformed Authorization header - Too short", http.StatusBadRequest)
		return "", nil, common.ErrMalformedAuthorization
	}

	// Check the format
	bearer := authorization[0:7]
	authorizationValue := authorization[7:]

	if bearer != "Bearer " {
		http.Error(writer, "Malformed authorization header - No Bearer found", http.StatusBadRequest)
		return "", nil, common.ErrMalformedAuthorization
	}

	// Split by the dots
	parts := strings.Split(authorizationValue, ".")
	if len(parts) != 3 {
		http.Error(writer, "Malformed Authorization header - Bad Bearer value", http.StatusBadRequest)
		return "", nil, common.ErrMalformedAuthorization
	}

	// Check the signature
	err := jwt.SigningMethodRS512.Verify(strings.Join(parts[0:2], "."), parts[2], validator.serverPublicKey)
	if err != nil {
		http.Error(writer, "Error while verifying the token - Bad signature", http.StatusUnauthorized)
		return "", nil, common.ErrSignatureInvalid
	}

	// Read the token
	tokenString := authorizationValue
	token, err := jwt.ParseWithClaims(tokenString, &common.CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return validator.serverPublicKey, nil
	})
	if err != nil {
		http.Error(writer, "Error while verifying the token - Malformed token", http.StatusUnauthorized)
		return "", nil, common.ErrTokenMalformed
	}

	// Read the claims
	claims, ok := token.Claims.(*common.CustomClaims) // claims.User and claims.Roles are what we are interested in.
	if !ok {
		http.Error(writer, "Error while verifying the token - Malformed claims", http.StatusUnauthorized)
		return "", nil, common.ErrTokenMalformed
	}

	// Read the timeout
	if claims.ExpiresAt < time.Now().Unix() {
		http.Error(writer, "Error while verifying the token - Token too old", http.StatusUnauthorized)
		return "", nil, common.ErrTokenTooOld
	}

	return claims.User, claims.Roles, nil
}
