package connector

import (
	"crypto/rsa"
	"errors"
	"io/ioutil"

	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	shared "bitbucket.org/ThomasWuillemin/easy-sso/shared"
	"github.com/dgrijalva/jwt-go"
)

type SsoConnector struct {
	Configuration   *ConnectorConfig
	ServerPublicKey *rsa.PublicKey
	Client          http.Client
}

var ErrKeyFileNotFound = errors.New("the requested key file cannot be found")
var EmptyResponseFromServer = errors.New("the response from the server was empty")

// NewSsoConnector allocates a new SsoClient with the given configuration
func NewSsoConnector(configuration *ConnectorConfig) (*SsoConnector, error) {

	// Read the key
	key, err := ioutil.ReadFile(configuration.PublicKeyPath)
	if err != nil {
		return nil, ErrKeyFileNotFound
	}
	parsedPubKey, err := jwt.ParseRSAPublicKeyFromPEM(key)
	if err != nil {
		return nil, err
	}

	// Use a client without redirect (done by hand)
	client := http.Client{
		CheckRedirect: noRedirectPolicy,
	}

	return &SsoConnector{
		Configuration:   configuration,
		ServerPublicKey: parsedPubKey,
		Client:          client,
	}, nil
}

func (client *SsoConnector) RequestToken(userName string, password string) (*shared.AuthenticationResponse, error) {

	// Prepare the base query
	requestGetTokenURL := client.Configuration.ServerBaseURL + "/token"
	requestGetTokenBody := strings.NewReader("username=" + userName + "&password=" + password)
	requestGetToken, err := http.NewRequest("POST", requestGetTokenURL, requestGetTokenBody)

	// Add the authentication to the server
	client.addAuthenticationHeader(requestGetToken)

	// Make the query
	responseGetToken, err := client.Client.Do(requestGetToken)
	if err != nil {
		return nil, err
	}
	defer responseGetToken.Body.Close()

	// Get the body of the query
	rawToken := getBody(responseGetToken)
	if rawToken == nil {
		return nil, EmptyResponseFromServer
	}

	var response shared.AuthenticationResponse
	if err := json.Unmarshal(rawToken.Bytes(), &response); err != nil {
		return nil, err
	}

	return &response, nil
}

func (client *SsoConnector) addAuthenticationHeader(request *http.Request) error {
	// If needed, add the authentication to the server
	if (client.Configuration.ServerClientId != nil) && (client.Configuration.ServerClientPassword != nil) {
		rawServerAuthentication := fmt.Sprintf("%s:%s", *client.Configuration.ServerClientId, *client.Configuration.ServerClientPassword)
		serverAuthentication := base64.StdEncoding.EncodeToString([]byte(rawServerAuthentication))
		request.Header.Add("Authorization", fmt.Sprintf("Basic %s", serverAuthentication))
	}
	return nil
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
