package connector

import (
	"encoding/json"
	"fmt"
	"os"
)

type ConnectorConfig struct {
	ServerBaseURL        string  `json:"serverBaseURL"`
	PublicKeyPath        string  `json:"publicKeyPath"`
	ServerClientId       *string `json:"clientId"`
	ServerClientPassword *string `json:"clientPassword"`
}

// LoadConfiguration loads the configuration file
func LoadConfiguration(file string) *ConnectorConfig {
	var config ConnectorConfig
	configFile, err := os.Open(file)
	defer configFile.Close()
	if err != nil {
		fmt.Println(err.Error())
	}
	jsonParser := json.NewDecoder(configFile)
	jsonParser.Decode(&config)
	return &config
}
