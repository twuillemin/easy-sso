package httpconnector

import (
	"errors"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	shared "bitbucket.org/ThomasWuillemin/easy-sso/shared"
	"crypto/x509"
	"io/ioutil"
	"os"
	"crypto/tls"
)

type HttpConnector struct {
	serverBaseURL                string
	serverPublicHTTPSCertificate string
	serverClientId               string
	serverClientPassword         string
	httpClient                   http.Client
}

var EmptyResponseFromServer = errors.New("the response from the server was empty")

// NewHttpConnector allocates a new HttpConnector with the given configuration
func NewHttpConnector(configuration *HttpConnectorConfig) (*HttpConnector, error) {

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

	// The Http client
	httpClient := &http.Client{
		CheckRedirect: noRedirectPolicy,
	}

	serverPublicHTTPSCertificate := ""
	if configuration.ServerPublicHTTPSCertificate != nil {
		serverPublicHTTPSCertificate = *configuration.ServerPublicHTTPSCertificate
	}

	// If a specific certificate is added
	if len(serverPublicHTTPSCertificate) > 0 {
		pool := x509.NewCertPool()

		certFile, err := os.Open(serverPublicHTTPSCertificate)
		defer certFile.Close()

		// Get the body of the query
		contents, err := ioutil.ReadAll(certFile)
		if err != nil {
			return nil, err
		}

		pool.AppendCertsFromPEM(contents)

		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		}
	}

	return &HttpConnector{
		serverBaseURL:                *configuration.ServerBaseURL,
		serverPublicHTTPSCertificate: serverPublicHTTPSCertificate,
		serverClientId:               clientId,
		serverClientPassword:         clientPassword,
		httpClient:                   *httpClient,
	}, nil
}

// RequestToken requests a new Token from the SSO server
func (client HttpConnector) RequestToken(userName string, password string) (*shared.AuthenticationResponse, error) {

	// Prepare the content of the query
	jsonRequest, err := json.Marshal(
		shared.TokenRequestBody{
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
		return nil, EmptyResponseFromServer
	}

	var response shared.AuthenticationResponse
	if err := json.Unmarshal(rawToken.Bytes(), &response); err != nil {
		return nil, err
	}

	return &response, nil
}

// RequestRefresh requests a refreshed Token from the SSO server
func (client HttpConnector) RequestRefresh(refreshToken string) (*shared.AuthenticationResponse, error) {

	// Prepare the content of the query
	jsonRequest, err := json.Marshal(
		shared.TokenRefreshBody{
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
		return nil, EmptyResponseFromServer
	}

	var response shared.AuthenticationResponse
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
