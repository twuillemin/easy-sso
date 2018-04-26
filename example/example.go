package main

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"bitbucket.org/ThomasWuillemin/easy-sso/client"
	"bitbucket.org/ThomasWuillemin/easy-sso/client/httpconnector"
	"bitbucket.org/ThomasWuillemin/easy-sso/server/server"
	"bitbucket.org/ThomasWuillemin/easy-sso/service/go-http"
	log "github.com/sirupsen/logrus"
)

func main() {

	// Start the server
	go server.StartServer("C:\\dev\\go\\src\\bitbucket.org\\ThomasWuillemin\\easy-sso\\example\\config_server.json")

	// Start the service 2
	go doService2()

	// Start the service 1
	go doService1()

	// Execute the client
	doClient()
}

// ------------------------------------------------------------------------------------------------
//
//                                   THE PURE CLIENT PART
//
// ------------------------------------------------------------------------------------------------

var ssoClient *client.SsoClient

func doClient() {

	// Load the config
	configuration, err := httpconnector.LoadConfiguration("C:\\dev\\go\\src\\bitbucket.org\\ThomasWuillemin\\easy-sso\\example\\config_client.json")
	if err != nil {
		log.Error("doClient: Unable to load the configuration: " + err.Error())
		return
	}

	// Create the SSO client
	ssoClient, err = client.NewSsoClient(configuration, "user", "user_password")
	if err != nil {
		log.Error("doClient: Unable to load the configuration: " + err.Error())
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
	ssoClient.AuthenticateRequest(requestGetHello)

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

	fmt.Printf("doClient: %s\n", string(contents))
}

// ------------------------------------------------------------------------------------------------
//
//                                   THE SERVICE + CLIENT PART
//
// ------------------------------------------------------------------------------------------------

var ssoClientService1 *client.SsoClient
var ssoService1 *go_http.SsoService

func doService1() {

	// Load the config as a client
	configurationClient, err := httpconnector.LoadConfiguration("C:\\dev\\go\\src\\bitbucket.org\\ThomasWuillemin\\easy-sso\\example\\config_client.json")
	if err != nil {
		log.Error("doService1: Unable to load the client configuration: " + err.Error())
		return
	}

	// Create the SSO client
	ssoClientService1, err = client.NewSsoClient(configurationClient, "admin", "admin_password")
	if err != nil {
		log.Error("doService1: Unable to load the client configuration: " + err.Error())
		return
	}

	// Load the config as a service
	configurationService, err := go_http.LoadConfiguration("C:\\dev\\go\\src\\bitbucket.org\\ThomasWuillemin\\easy-sso\\example\\config_service.json")
	if err != nil {
		log.Error("doService1: Unable to load the service configuration: " + err.Error())
		return
	}

	// Create the SSO service
	ssoService1, err = go_http.NewSsoService(configurationService)
	if err != nil {
		log.Error("doService1: Unable to load the service configuration: " + err.Error())
		return
	}

	log.Info("doService1: Ready to serve")

	http.HandleFunc("/hello1", handleHello1)

	http.ListenAndServe(":8080", nil)
}

func handleHello1(writer http.ResponseWriter, request *http.Request) {

	username, roles, err := ssoService1.GetUserFromHeaderOrFail(writer, request)
	if err != nil {
		log.Error("handleHello1: Unable to authenticate user: " + err.Error())
		return
	}

	log.Info("handleHello1: Received a query from: ", username, ", roles: ", roles)

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
	ssoClientService1.AuthenticateRequest(requestGetHello)

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

	writer.WriteHeader(http.StatusOK)
	fmt.Fprint(writer, string(contents))
}

// ------------------------------------------------------------------------------------------------
//
//                                   THE PURE SERVICE
//
// ------------------------------------------------------------------------------------------------

var ssoService2 *go_http.SsoService

func doService2() {

	// Load the config as a service
	configurationService, err := go_http.LoadConfiguration("C:\\dev\\go\\src\\bitbucket.org\\ThomasWuillemin\\easy-sso\\example\\config_service.json")
	if err != nil {
		log.Error("doService2: Unable to load the service configuration: " + err.Error())
		return
	}

	// Create the SSO service
	ssoService2, err = go_http.NewSsoService(configurationService)
	if err != nil {
		log.Error("doService2: Unable to load the service configuration: " + err.Error())
		return
	}

	http.HandleFunc("/hello2", handleHello2)

	log.Info("doService2: Ready to serve")

	http.ListenAndServe(":8081", nil)
}

func handleHello2(writer http.ResponseWriter, request *http.Request) {

	username, roles, err := ssoService2.GetUserFromHeaderOrFail(writer, request)
	if err != nil {
		log.Error("handleHello2: Unable to authenticate user: " + err.Error())
		return
	}

	log.Info("handleHello2: Received a query from: ", username, ", roles: ", roles)

	writer.WriteHeader(http.StatusOK)
	fmt.Fprint(writer, "Hello as an admin")
}
