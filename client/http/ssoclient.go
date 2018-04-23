package http

import (
	"log"
	"net/http"
	"strings"

	"bitbucket.org/ThomasWuillemin/easy-sso/client/connector"
	"github.com/dgrijalva/jwt-go"
	"github.com/samitpal/simple-sso/util"
)

var ssoConnector *connector.SsoConnector

func InitializeSsoConnection() {
	// Todo
}

func GetUserFromTokenOrFail(writer http.ResponseWriter, request *http.Request) {
	authorization := request.Header.Get("Authorization")

	// If no authorization (8 is the minimum for Bearer + 1 char token)
	if len(authorization) < 8 {
		http.Error(writer, "No valid Authorization header", http.StatusUnauthorized)
		return
	}

	// Check the format
	bearer := authorization[0:7]
	authorizationValue := authorization[7:]

	if bearer != "Bearer " {
		http.Error(writer, "Malformed authorization header", http.StatusBadRequest)
		return
	}

	parts := strings.Split(authorizationValue, ".")
	err := jwt.SigningMethodRS512.Verify(strings.Join(parts[0:2], "."), parts[2], ssoConnector.ServerPublicKey)
	if err != nil {
		log.Fatalf("[%v] Error while verifying key: %v", parts[1], err)
	}

	tokenString := parts[1]
	token, err := jwt.ParseWithClaims(tokenString, &util.CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return ssoConnector.ServerPublicKey, nil
	})

	claims, ok := token.Claims.(*util.CustomClaims) // claims.User and claims.Roles are what we are interested in.
	if !ok {
		log.Fatalf("[%v] Error while verifying key: %v", parts[1], err)
	}

	log.Printf("Claims: [%v]", claims)
}
