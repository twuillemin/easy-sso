package main

import (
	"bitbucket.org/ThomasWuillemin/easy-sso/server/config"
	"bitbucket.org/ThomasWuillemin/easy-sso/server/sso"
	"bitbucket.org/ThomasWuillemin/easy-sso/server/server"
	log "github.com/sirupsen/logrus"
	"errors"
	"os"
)

var ssoEngine *sso.SsoEngine
var configFileName string
var configuration *config.Config

var (
	ErrNoAuthorization = errors.New("the query does not have a valid Authorization")
)

func main() {

	// Use the fine given as parameter or the default configuration
	configFileNameToUse := "config.json"
	argsWithoutProg := os.Args[1:]
	if len(argsWithoutProg) == 0 {
		log.Warn("No configuration file given as parameter. Try to load config.json")
	} else {
		configFileNameToUse = argsWithoutProg[0]
	}

	server.StartServer(configFileNameToUse)
}
