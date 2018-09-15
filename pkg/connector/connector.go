package connector

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"os"
)

// NewClient allocates a new SsoClient with the given connector
func NewClient(connector Connector, userName string, password string) (Client, error) {

	if connector == nil {
		log.Error("No connector was given for the client to connect")
		return nil, fmt.Errorf("no connector was given for the client to connect")
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

	return &clientImpl{
		connector:      connector,
		authentication: *authentication,
		expireAt:       expireAt,
	}, nil
}

// NewConnector allocates a new SsoClient with the given configuration
func NewConnector(configuration *AuthConnectorConfig) (Connector, error) {

	// Validate that the configuration was given and is decent
	if err := ValidateConfiguration(configuration); err != nil {
		log.Error("Unable to use the configuration for connector.")
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

	return &connectorImpl{
		serverBaseURL:                *configuration.ServerBaseURL,
		serverPublicHTTPSCertificate: serverPublicHTTPSCertificate,
		serverClientId:               clientId,
		serverClientPassword:         clientPassword,
		httpClient:                   *httpClient,
	}, nil

}
