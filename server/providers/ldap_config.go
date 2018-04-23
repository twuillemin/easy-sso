package providers

import (
	log "github.com/sirupsen/logrus"
)

type LdapProviderConfig struct {
	Host         *string `json:"host"`
	Port         *int    `json:"port"`
	Ssl          *bool   `json:"ssl"`
	BaseDN       *string `json:"baseDN"`
	BindDN       *string `json:"bindDN"`
	BindPassword *string `json:"bindPassword"`
}

func readLdapConfiguration(configuration *LdapProviderConfig) error {

	if configuration == nil {
		log.Error("Configuration for LDAP is missing")
		return ErrBadConfiguration
	}

	if configuration.Host == nil {
		log.Error("Configuration for LDAP is missing the definition for host attribute")
		return ErrBadConfiguration
	}

	if configuration.Port == nil {
		log.Error("Configuration for LDAP is missing the definition for port attribute")
		return ErrBadConfiguration
	}

	if configuration.Ssl == nil {
		log.Error("Configuration for LDAP is missing the definition for ssl attribute")
		return ErrBadConfiguration
	}

	if configuration.BaseDN == nil {
		log.Error("Configuration for LDAP is missing the definition for baseDN attribute")
		return ErrBadConfiguration
	}

	if configuration.BindDN == nil {
		log.Error("Configuration for LDAP is missing the definition for bindDN attribute")
		return ErrBadConfiguration
	}

	if configuration.BindPassword == nil {
		log.Error("Configuration for LDAP is missing the definition for bindPassword attribute")
		return ErrBadConfiguration
	}

	return nil
}
