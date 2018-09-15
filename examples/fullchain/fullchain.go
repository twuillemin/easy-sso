package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"

	"bitbucket.org/ThomasWuillemin/easy-sso/pkg/common"
	"bitbucket.org/ThomasWuillemin/easy-sso/pkg/connector"
	"bitbucket.org/ThomasWuillemin/easy-sso/pkg/server"
	"bitbucket.org/ThomasWuillemin/easy-sso/pkg/validator"
	log "github.com/sirupsen/logrus"
)

const basePath string = "C:\\Users\\thwui\\go\\src\\bitbucket.org\\ThomasWuillemin\\easy-sso\\examples\\fullchain"

func init() {
	// Log as JSON instead of the default ASCII formatter.
	log.SetFormatter(&log.JSONFormatter{})

	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	log.SetOutput(os.Stdout)

	// Only log the warning severity or above.
	log.SetLevel(log.DebugLevel)
}

func main() {

	err := os.Chdir(basePath)
	if err != nil {
		panic(err)
	}

	// Load the configuration
	configuration, err := loadFullChainConfiguration("config.json")
	if err != nil {
		log.Error("Unable to load configuration.")
		return
	}

	// -----------------------------------------------
	// Start the server
	// -----------------------------------------------
	go doServer(configuration.Server, configuration.AuthServerConfig)

	// -----------------------------------------------
	// Start the admin service
	// -----------------------------------------------
	go doService2(configuration.AuthValidatorConfig)

	// -----------------------------------------------
	// Start the user service
	// -----------------------------------------------
	go doService1(configuration.AuthConnectorConfig, configuration.AuthValidatorConfig)

	// -----------------------------------------------
	// Start the client
	// -----------------------------------------------
	doClient(configuration.AuthConnectorConfig)
}

func doServer(
	serverConfiguration *ServerConfig,
	authServerConfiguration *server.Configuration) {
	// Create the http mux that will host the authServer
	mixedHTTPServer := http.NewServeMux()

	// Create the authServer(without reload capacity for this example)
	server.AddServer(
		authServerConfiguration,
		nil,
		mixedHTTPServer,
		mixedHTTPServer)

	// Create the REST server
	if (serverConfiguration.HttpsCertificate != nil) && (serverConfiguration.HttpsCertificateKey != nil) {
		http.ListenAndServeTLS(
			":"+strconv.Itoa(serverConfiguration.Port),
			*serverConfiguration.HttpsCertificate,
			*serverConfiguration.HttpsCertificateKey,
			mixedHTTPServer)
	} else {
		http.ListenAndServe(":"+strconv.Itoa(serverConfiguration.Port), mixedHTTPServer)
	}
}

// ------------------------------------------------------------------------------------------------
//
//                                   THE PURE CLIENT PART
//
// ------------------------------------------------------------------------------------------------

func doClient(configuration *connector.AuthConnectorConfig) {

	// Create a connection to the server
	connection, err := connector.NewConnector(configuration)
	if err != nil {
		log.Error("doClient: Unable to create a connector: " + err.Error())
		return
	}

	// Create a client
	client, err := connector.NewClient(connection, "user", "user_password")
	if err != nil {
		log.Error("doClient: Unable to create a client: " + err.Error())
		return
	}

	// Make a request for getting hello
	requestGetHello, err := http.NewRequest(
		"GET",
		"http://localhost:8080/hello1",
		nil)
	if err != nil {
		log.Error("doClient: Unable to create request: " + err.Error())
		return
	}

	// Add authentication to the request
	client.AuthenticateRequest(requestGetHello)

	fmt.Printf("-client: Making query to hello1\n")

	// Make the query
	responseGetHello, err := new(http.Client).Do(requestGetHello)
	if err != nil {
		log.Error("doClient: Unable to do the request: " + err.Error())
		return
	}

	// Get the body of the query
	contents, err := ioutil.ReadAll(responseGetHello.Body)
	if err != nil {
		log.Error("doClient: Unable to read the response: " + err.Error())
		return
	}

	fmt.Printf("-client: Received reply %s\n", string(contents))
}

// ------------------------------------------------------------------------------------------------
//
//               THE SERVICE + CLIENT PART (SERVICE 1 - EXPECT USER - CONNECT AS ADMIN)
//
// ------------------------------------------------------------------------------------------------

func doService1(configurationConnector *connector.AuthConnectorConfig, configurationValidator *validator.Configuration) {

	// Create a connection to the server
	connection, err := connector.NewConnector(configurationConnector)
	if err != nil {
		log.Error("doService1: Unable to create a connector: " + err.Error())
		return
	}

	// Create a client
	client, err := connector.NewClient(connection, "admin", "admin_password")
	if err != nil {
		log.Error("doClient: Unable to create a client: " + err.Error())
		return
	}

	// Create a authValidator
	authValidator, err := validator.New(configurationValidator)
	if err != nil {
		log.Error("doClient: Unable to create a authValidator: " + err.Error())
		return
	}

	log.Info("doService1: Ready to serve")

	// Create an handler for the /hello1 endpoint
	http.HandleFunc(
		"/hello1",
		func(writer http.ResponseWriter, request *http.Request) {

			// Read the token from the query
			username, roles, err := authValidator.GetUserFromHeaderOrFail(writer, request)
			if err != nil {
				log.Error("handleHello1: Unable to authenticate user: " + err.Error())
				return
			}

			fmt.Printf("/hello1: Received a query from: %v, roles %v\n", username, roles)

			// Make a request for getting hello
			requestGetHello, err := http.NewRequest(
				"GET",
				"http://localhost:8081/hello2",
				nil)
			if err != nil {
				writer.WriteHeader(http.StatusInternalServerError)
				log.Error("handleHello1: Unable to create request: " + err.Error())
				return
			}

			// Add authentication to the request
			client.AuthenticateRequest(requestGetHello)

			fmt.Printf("/hello1: Making query to hello2\n")

			// Make the query
			responseGetHello, err := new(http.Client).Do(requestGetHello)
			if err != nil {
				writer.WriteHeader(http.StatusInternalServerError)
				log.Error("handleHello1: Unable to do the request: " + err.Error())
				return
			}

			// Get the body of the query
			contents, err := ioutil.ReadAll(responseGetHello.Body)
			if err != nil {
				writer.WriteHeader(http.StatusInternalServerError)
				log.Error("handleHello1: Unable to read the response: " + err.Error())
				return
			}

			fmt.Printf("/hello1: Received reply %s\n", string(contents))

			writer.WriteHeader(http.StatusOK)
			fmt.Fprint(writer, string(contents))

			fmt.Printf("/hello1: Replied to the query\n")
		})

	log.Info("doService1: Ready to serve")

	http.ListenAndServe(":8080", nil)
}

// ------------------------------------------------------------------------------------------------
//
//                          THE PURE SERVICE (SERVICE 2 - EXPECT ADMIN)
//
// ------------------------------------------------------------------------------------------------

func doService2(configuration *validator.Configuration) {

	// Create a authValidator
	authValidator, err := validator.New(configuration)
	if err != nil {
		log.Error("doClient: Unable to create a authValidator: " + err.Error())
		return
	}

	// Create an handler for the /hello2 endpoint
	http.HandleFunc(
		"/hello2",
		func(writer http.ResponseWriter, request *http.Request) {

			// Read the token from the query
			username, roles, err := authValidator.GetUserFromHeaderOrFail(writer, request)
			if err != nil {
				log.Error("handleHello2: Unable to authenticate user: " + err.Error())
				return
			}

			fmt.Printf("/hello2: Received a query from: %v, roles %v\n", username, roles)

			writer.WriteHeader(http.StatusOK)
			fmt.Fprint(writer, "Hello from admin")

			fmt.Printf("/hello2: Replied to the query\n")
		})

	log.Info("doService2: Ready to serve")

	http.ListenAndServe(":8081", nil)
}

type Config struct {
	Server              *ServerConfig                  `json:"server"`
	AuthServerConfig    *server.Configuration          `json:"authserver"`
	AuthValidatorConfig *validator.Configuration       `json:"authvalidator"`
	AuthConnectorConfig *connector.AuthConnectorConfig `json:"authconnector"`
}

type ServerConfig struct {
	Port                int     `json:"port"`
	HttpsCertificate    *string `json:"httpsCertificate"`
	HttpsCertificateKey *string `json:"httpsCertificateKey"`
}

// loadFullChainConfiguration loads the configuration file
func loadFullChainConfiguration(configFileName string) (*Config, error) {

	// Try to open the file
	configFile, err := os.Open(configFileName)
	defer configFile.Close()

	if err != nil {
		return nil, err
	}
	jsonParser := json.NewDecoder(configFile)

	// Read the JSON
	var configuration Config
	jsonParser.Decode(&configuration)

	// Check that the JSON has everything needed
	if configuration.Server == nil {
		log.Error("Configuration for the server is missing")
		return nil, common.ErrBadConfiguration
	}

	if configuration.AuthServerConfig == nil {
		log.Error("Configuration for the server is missing")
		return nil, common.ErrBadConfiguration
	}

	if configuration.AuthValidatorConfig == nil {
		log.Error("Configuration for the authvalidtor is missing")
		return nil, common.ErrBadConfiguration
	}

	if configuration.AuthConnectorConfig == nil {
		log.Error("Configuration for the connector is missing")
		return nil, common.ErrBadConfiguration
	}

	// Check that the example server is ok
	if configuration.Server.Port < 0 || configuration.Server.Port > 65535 {
		log.Error("Configuration for the server port must have a value between 0 and 65535")
		return nil, common.ErrBadConfiguration
	}

	// Check the included configurations
	err = server.ValidateConfiguration(configuration.AuthServerConfig)
	if err != nil {
		log.Error("Unable to use the configuration.")
		return nil, common.ErrBadConfiguration
	}

	err = validator.ValidateConfiguration(configuration.AuthValidatorConfig)
	if err != nil {
		log.Error("Unable to use the configuration.")
		return nil, common.ErrBadConfiguration
	}

	err = connector.ValidateConfiguration(configuration.AuthConnectorConfig)
	if err != nil {
		log.Error("Unable to use the configuration.")
		return nil, common.ErrBadConfiguration
	}

	return &configuration, nil
}
