package config

import (
	"encoding/json"
	"os"

	"bitbucket.org/ThomasWuillemin/easy-sso/server/providers"
	"bitbucket.org/ThomasWuillemin/easy-sso/server/sso"
)

type ServerConfig struct {
	Port                int     `json:"port"`
	HttpsCertificate    *string `json:"httpsCertificate"`
	HttpsCertificateKey *string `json:"httpsCertificateKey"`
	ClientId            *string `json:"clientId"`
	ClientPassword      *string `json:"clientPassword"`
}

type Config struct {
	Server *ServerConfig                  `json:"server"`
	Sso    *sso.SsoConfig                 `json:"sso"`
	Ldap   *providers.LdapProviderConfig  `json:"ldap"`
	Basic  *providers.BasicProviderConfig `json:"basic"`
}

// LoadConfiguration loads the configuration file
func LoadConfiguration(file string) (*Config, error) {

	configFile, err := os.Open(file)
	defer configFile.Close()

	if err != nil {
		return nil, err
	}
	jsonParser := json.NewDecoder(configFile)

	var config Config
	jsonParser.Decode(&config)

	return &config, nil
}
