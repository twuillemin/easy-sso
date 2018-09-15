package connector

import (
	"bitbucket.org/ThomasWuillemin/easy-sso/pkg/common"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"io"
	"net/http"
)

type connectorImpl struct {
	serverBaseURL                string
	serverPublicHTTPSCertificate string
	serverClientId               string
	serverClientPassword         string
	httpClient                   http.Client
}

// RequestToken requests a new Token from the SSO server
func (client connectorImpl) RequestToken(userName string, password string) (*common.AuthenticationResponse, error) {

	// Prepare the content of the query
	jsonRequest, err := json.Marshal(
		common.TokenRequestBody{
			UserName: userName,
			Password: password,
		})
	if err != nil {
		return nil, err
	}

	// Prepare the base query
	requestGetToken, err := http.NewRequest(
		"POST",
		client.serverBaseURL+"/token",
		bytes.NewBuffer(jsonRequest))
	if err != nil {
		return nil, err
	}

	// Add the authentication to the server
	if len(client.serverClientId) > 0 {
		requestGetToken.SetBasicAuth(client.serverClientId, client.serverClientPassword)
	}

	// Add the ContentType
	requestGetToken.Header.Add("Content-Type", "application/json")

	// Make the query
	responseGetToken, err := client.httpClient.Do(requestGetToken)
	if err != nil {
		return nil, err
	}
	defer responseGetToken.Body.Close()

	// Get the body of the query
	rawToken := getBody(responseGetToken)
	if rawToken == nil {
		return nil, common.EmptyResponseFromServer
	}

	var response common.AuthenticationResponse
	if err := json.Unmarshal(rawToken.Bytes(), &response); err != nil {
		return nil, err
	}

	return &response, nil
}

// RequestRefresh requests a refreshed Token from the SSO server
func (client connectorImpl) RequestRefresh(refreshToken string) (*common.AuthenticationResponse, error) {

	// Prepare the content of the query
	jsonRequest, err := json.Marshal(
		common.TokenRefreshBody{
			RefreshToken: refreshToken,
		})
	if err != nil {
		return nil, err
	}

	// Prepare the base query
	requestGetToken, err := http.NewRequest(
		"POST",
		client.serverBaseURL+"/refresh",
		bytes.NewBuffer(jsonRequest))
	if err != nil {
		return nil, err
	}

	// Add the authentication to the server
	if len(client.serverClientId) > 0 {
		requestGetToken.SetBasicAuth(client.serverClientId, client.serverClientPassword)
	}

	// Add the mandatory ContentType
	requestGetToken.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Make the query
	responseGetToken, err := client.httpClient.Do(requestGetToken)
	if err != nil {
		return nil, err
	}
	defer responseGetToken.Body.Close()

	// Get the body of the query
	rawToken := getBody(responseGetToken)
	if rawToken == nil {
		return nil, common.EmptyResponseFromServer
	}

	var response common.AuthenticationResponse
	if err := json.Unmarshal(rawToken.Bytes(), &response); err != nil {
		return nil, err
	}

	return &response, nil
}

// Define a non redirecting policy. Useful when doing queries that are redirecting as go
// is automatically following the redirect
func noRedirectPolicy(_ *http.Request, _ []*http.Request) error {

	return http.ErrUseLastResponse
}

// Retrieve the body of a response as a bytes buffer. This method
// is able to receive non compressed bodies and gziped ones
func getBody(response *http.Response) *bytes.Buffer {

	if response == nil {
		return nil
	}

	// Check that the server actually sent compressed data
	var reader io.ReadCloser
	switch response.Header.Get("Content-Encoding") {
	case "gzip":
		reader, _ = gzip.NewReader(response.Body)
		defer reader.Close()
	default:
		reader = response.Body
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(reader)
	return buf
}

// AuthenticateRequest adds the Authorization bearer information to the given query.
func getExpirationFromToken(accessToken string) (int64, error) {

	// Read the token without validating it
	token, _, err := new(jwt.Parser).ParseUnverified(accessToken, &common.CustomClaims{})
	if err != nil {
		return 0, common.ErrTokenMalformed
	}

	// Read the claims
	claims, ok := token.Claims.(*common.CustomClaims) // claims.User and claims.Roles are what we are interested in.
	if !ok {
		return 0, common.ErrTokenMalformed
	}

	return claims.ExpiresAt, nil
}
