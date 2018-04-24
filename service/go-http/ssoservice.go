package go_http

import (
	"net/http"
	"strings"

	"crypto/rsa"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/samitpal/simple-sso/util"
	"time"
)

type SsoService struct {
	serverPublicKey *rsa.PublicKey
}

var (
	ErrNoAuthorization        = errors.New("no Authorization received in the query")
	ErrMalformedAuthorization = errors.New("the received Authorization is malformed")
	ErrSignatureInvalid       = errors.New("the signature of the token can not be verified")
	ErrTokenMalformed         = errors.New("the token is too malformed")
	ErrTokenTooOld            = errors.New("the token is too old")
)

// NewSsoEngine allocates a new SsoEngine with the given configuration
func NewSsoEngine(configuration *SsoServiceConfig) (*SsoService, error) {

	publicKey, err := readConfiguration(configuration)
	if err != nil {
		return nil, err
	}

	return &SsoService{
		serverPublicKey: publicKey,
	}, nil
}

// GetUserFromTokenOrFail is be inserted at beginning of each endpoint for ensuring that
// the authentication token is present and valid
func (ssoService *SsoService) GetUserFromHeaderOrFail(writer http.ResponseWriter, request *http.Request) (string, []string, error) {
	authorization := request.Header.Get("Authorization")

	// If no authorization (8 is the minimum for Bearer + 1 char token)
	if len(authorization) == 0 {
		http.Error(writer, "No valid Authorization header", http.StatusUnauthorized)
		return "", nil, ErrNoAuthorization
	}

	// If no authorization (8 is the minimum for Bearer + 1 char token)
	if len(authorization) < 8 {
		http.Error(writer, "Malformed Authorization header - Too short", http.StatusBadRequest)
		return "", nil, ErrMalformedAuthorization
	}

	// Check the format
	bearer := authorization[0:7]
	authorizationValue := authorization[7:]

	if bearer != "Bearer " {
		http.Error(writer, "Malformed authorization header - No Bearer found", http.StatusBadRequest)
		return "", nil, ErrMalformedAuthorization
	}

	// Split by the dots
	parts := strings.Split(authorizationValue, ".")
	if len(parts) != 3 {
		http.Error(writer, "Malformed Authorization header - Bad Bearer value", http.StatusBadRequest)
		return "", nil, ErrMalformedAuthorization
	}

	// Check the signature
	err := jwt.SigningMethodRS512.Verify(strings.Join(parts[0:2], "."), parts[2], ssoService.serverPublicKey)
	if err != nil {
		http.Error(writer, "Error while verifying the token - Bad signature", http.StatusUnauthorized)
		return "", nil, ErrSignatureInvalid
	}

	// Read the token
	tokenString := parts[1]
	token, err := jwt.ParseWithClaims(tokenString, &util.CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return ssoService.serverPublicKey, nil
	})
	if err != nil {
		http.Error(writer, "Error while verifying the token - Malformed token", http.StatusUnauthorized)
		return "", nil, ErrTokenMalformed
	}

	// Read the claims
	claims, ok := token.Claims.(*util.CustomClaims) // claims.User and claims.Roles are what we are interested in.
	if !ok {
		http.Error(writer, "Error while verifying the token - Malformed claims", http.StatusUnauthorized)
		return "", nil, ErrTokenMalformed
	}

	// Read the timeout
	if claims.ExpiresAt < time.Now().Unix() {
		http.Error(writer, "Error while verifying the token - Token too old", http.StatusUnauthorized)
		return "", nil, ErrTokenTooOld
	}

	return claims.User, claims.Roles, nil
}
