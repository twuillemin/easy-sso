package server

import (
	"bitbucket.org/ThomasWuillemin/easy-sso/pkg/common"
	log "github.com/sirupsen/logrus"
	"os"
)

type Configuration struct {
	Sso   *SsoConfiguration           `json:"sso"`
	Ldap  *LdapProviderConfiguration  `json:"ldap"`
	Basic *BasicProviderConfiguration `json:"basic"`
}

// SsoConfiguration contains the general parameters for the SSO server
type SsoConfiguration struct {
	ClientId             *string    `json:"clientId"`
	ClientPassword       *string    `json:"clientPassword"`
	PrivateKeyPath       *string    `json:"privateKeyPath"`
	TokenSecondsToLive   *int64     `json:"tokenSecondsToLive"`
	RefreshSecondsToLive *int64     `json:"refreshSecondsToLive"`
	Providers            *[]*string `json:"providers"`
}

// LdapProviderConfiguration contains the parameters for connecting to a LDAP server for client authentication
type LdapProviderConfiguration struct {
	Host         *string `json:"host"`
	Port         *int    `json:"port"`
	Ssl          *bool   `json:"ssl"`
	BaseDN       *string `json:"baseDN"`
	BindDN       *string `json:"bindDN"`
	BindPassword *string `json:"bindPassword"`
}

// BasicProviderConfiguration contains the parameters for keeping the user and their roles hard-coded
type BasicProviderConfiguration struct {
	Users *[]*BasicProviderUserConfiguration `json:"users"`
}

// BasicProviderUserConfiguration contains a single user definition
type BasicProviderUserConfiguration struct {
	UserName *string    `json:"userName"`
	Password *string    `json:"password"`
	Roles    *[]*string `json:"roles"`
}

// ValidateConfiguration validates the configuration file
func ValidateConfiguration(configuration *Configuration) error {

	if configuration == nil {
		log.Error("Configuration for server is missing")
		return common.ErrBadConfiguration
	}

	// Validate mandatory elements
	err := validateSsoConfiguration(configuration.Sso)
	if err != nil {
		return err
	}

	// Validate optional parameters if present
	if configuration.Ldap != nil {
		err = validateLdapConfiguration(configuration.Ldap)
		if err != nil {
			return err
		}
	}

	if configuration.Basic != nil {
		err = validateBasicConfiguration(configuration.Basic)
		if err != nil {
			return err
		}
	}

	return nil
}

// validateSsoConfiguration reads the configuration and perform various tests ensuring the the configuration is ok
func validateSsoConfiguration(configuration *SsoConfiguration) error {

	if configuration == nil {
		log.Error("Configuration for Sso is missing")
		return common.ErrBadConfiguration
	}

	// Basic tests
	if configuration.PrivateKeyPath == nil {
		log.Error("Configuration for SSO is missing the definition for privateKeyPath attribute")
		return common.ErrBadConfiguration
	}
	if configuration.TokenSecondsToLive == nil {
		log.Error("Configuration for SSO is missing the definition for tokenSecondsToLive attribute")
		return common.ErrBadConfiguration
	}
	if configuration.RefreshSecondsToLive == nil {
		log.Error("Configuration for SSO is missing the definition for refreshSecondsToLive attribute")
		return common.ErrBadConfiguration
	}
	if configuration.Providers == nil || len(*configuration.Providers) == 0 {
		log.Error("Configuration for SSO is missing the definition for providers attribute")
		return common.ErrBadConfiguration
	}
	if len(*configuration.Providers) > 2 {
		log.Error("Configuration for SSO, attribute providers is limited to two entries")
		return common.ErrBadConfiguration
	}
	if len(*configuration.Providers) == 2 {
		// Just in case we have someone having fun
		if *(*configuration.Providers)[0] == *(*configuration.Providers)[1] {
			log.Error("Configuration for SSO, attribute providers must specify different provider for each entry")
			return common.ErrBadConfiguration
		}
	}

	if (configuration.ClientId != nil) && (configuration.ClientPassword == nil) {
		log.Error("Configuration for SSO, a client id was given but without a client password")
		return common.ErrBadConfiguration
	}
	if (configuration.ClientId == nil) && (configuration.ClientPassword != nil) {
		log.Error("Configuration for SSO, a client password was given but without a client id")
		return common.ErrBadConfiguration
	}

	// More advanced test
	if _, err := os.Stat(*configuration.PrivateKeyPath); os.IsNotExist(err) {
		log.Error("Configuration for SSO, attribute tokenCertificate is referencing a not existing file")
		return common.ErrBadConfiguration
	}
	if *configuration.TokenSecondsToLive < 0 {
		log.Error("Configuration for SSO, attribute tokenSecondsToLive can not be less than 0")
		return common.ErrBadConfiguration
	}
	if *configuration.RefreshSecondsToLive < 0 {
		log.Error("Configuration for SSO, attribute refreshSecondsToLive can not be less than 0")
		return common.ErrBadConfiguration
	}
	if *configuration.RefreshSecondsToLive <= *configuration.TokenSecondsToLive {
		log.Error("Configuration for SSO, attribute refreshSecondsToLive can not be less than tokenSecondsToLive")
		return common.ErrBadConfiguration
	}

	return nil
}

func validateLdapConfiguration(configuration *LdapProviderConfiguration) error {

	if configuration == nil {
		log.Error("Configuration for LDAP is missing")
		return common.ErrBadConfiguration
	}

	if configuration.Host == nil {
		log.Error("Configuration for LDAP is missing the definition for host attribute")
		return common.ErrBadConfiguration
	}

	if configuration.Port == nil {
		log.Error("Configuration for LDAP is missing the definition for port attribute")
		return common.ErrBadConfiguration
	}

	if configuration.Ssl == nil {
		log.Error("Configuration for LDAP is missing the definition for ssl attribute")
		return common.ErrBadConfiguration
	}

	if configuration.BaseDN == nil {
		log.Error("Configuration for LDAP is missing the definition for baseDN attribute")
		return common.ErrBadConfiguration
	}

	if configuration.BindDN == nil {
		log.Error("Configuration for LDAP is missing the definition for bindDN attribute")
		return common.ErrBadConfiguration
	}

	if configuration.BindPassword == nil {
		log.Error("Configuration for LDAP is missing the definition for bindPassword attribute")
		return common.ErrBadConfiguration
	}

	return nil
}

func validateBasicConfiguration(configuration *BasicProviderConfiguration) error {

	if configuration == nil {
		log.Error("Configuration for Basic is missing")
		return common.ErrBadConfiguration
	}

	if configuration.Users == nil {
		log.Error("Configuration for Basic is missing the definition for users attribute")
		return common.ErrBadConfiguration
	}

	if len(*configuration.Users) == 0 {
		log.Error("Configuration for Basic is missing has an empty list of users")
		return common.ErrBadConfiguration
	}

	return nil
}
