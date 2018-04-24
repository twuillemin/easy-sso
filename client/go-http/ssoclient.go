package go_http

import (
	"errors"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	shared "bitbucket.org/ThomasWuillemin/easy-sso/shared"
)

type SsoClient struct {
	serverBaseURL        string
	serverClientId       string
	serverClientPassword string
	httpClient           http.Client
}

var EmptyResponseFromServer = errors.New("the response from the server was empty")

// NewSsoConnector allocates a new SsoClient with the given configuration
func NewSsoClient(configuration *SsoClientConfig) (*SsoClient, error) {

	err := readConfiguration(configuration)
	if err != nil {
		return nil, err
	}

	clientId := ""
	clientPassword := ""
	if configuration.ServerClientId != nil {
		clientId = *configuration.ServerClientId
		clientPassword = *configuration.ServerClientPassword
	}

	return &SsoClient{
		serverBaseURL:        *configuration.ServerBaseURL,
		serverClientId:       clientId,
		serverClientPassword: clientPassword,
		httpClient: http.Client{
			CheckRedirect: noRedirectPolicy,
		},
	}, nil
}

// RequestToken requests a new Token from the SSO server
func (client *SsoClient) RequestToken(userName string, password string) (*shared.AuthenticationResponse, error) {

	// Prepare the base query
	requestGetTokenURL := client.serverBaseURL + "/token"
	requestGetTokenBody := strings.NewReader("username=" + userName + "&password=" + password)
	requestGetToken, err := http.NewRequest("POST", requestGetTokenURL, requestGetTokenBody)

	// Add the authentication to the server
	client.addAuthenticationHeader(requestGetToken)

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
		return nil, EmptyResponseFromServer
	}

	var response shared.AuthenticationResponse
	if err := json.Unmarshal(rawToken.Bytes(), &response); err != nil {
		return nil, err
	}

	return &response, nil
}

// RequestRefresh requests a refreshed Token from the SSO server
func (client *SsoClient) RequestRefresh(refreshToken string) (*shared.AuthenticationResponse, error) {

	// Prepare the base query
	requestGetTokenURL := client.serverBaseURL + "/refresh"
	requestGetTokenBody := strings.NewReader("refresh_token=" + refreshToken)
	requestGetToken, err := http.NewRequest("POST", requestGetTokenURL, requestGetTokenBody)

	// Add the authentication to the server
	client.addAuthenticationHeader(requestGetToken)

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
		return nil, EmptyResponseFromServer
	}

	var response shared.AuthenticationResponse
	if err := json.Unmarshal(rawToken.Bytes(), &response); err != nil {
		return nil, err
	}

	return &response, nil
}

func (client *SsoClient) addAuthenticationHeader(request *http.Request) error {
	// If needed, add the authentication to the server
	if len(client.serverClientId) > 0 {
		rawServerAuthentication := fmt.Sprintf("%s:%s", client.serverClientId, client.serverClientPassword)
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
