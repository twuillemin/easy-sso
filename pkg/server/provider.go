package server

import (
	log "github.com/sirupsen/logrus"
	"github.com/twuillemin/easy-sso-common/pkg/common"
)

// authenticationProvider is what it needs to be implemented for authentication functionality.
type authenticationProvider interface {
	// Auth takes user,password strings as arguments and returns the user, user roles (e.g providers groups)
	// (string slice) if the call succeeds. Auth should return the ErrUnAuthorized or ErrUserNotFound error if
	// auth fails or if the user is not found respectively.
	Authenticate(userName string, password string) (*authenticatedUser, error)
}

// authenticatedUser is the structure keeping all the information about a user that has been successfully authenticated
type authenticatedUser struct {
	UserName string
	Roles    []string
}

// newAuthenticationProvider takes a configuration and try to build the list of providers that are configured
func newAuthenticationProvider(configuration *Configuration) ([]authenticationProvider, error) {

	if configuration == nil {
		log.Error("newAuthenticationProvider : parameter configuration was given null")
		return nil, common.ErrBadConfiguration
	}

	// Try to build the providers
	ssoProviders := make([]authenticationProvider, 0, len(*configuration.Sso.Providers))
	for _, providerName := range *configuration.Sso.Providers {
		if *providerName == "basic" {

			// If no configuration
			if configuration.Basic == nil {
				log.Error("Configuration for SSO, attribute providers is set to use the \"basic\" provider, but this provider is not defined in the configuration")
				return nil, common.ErrBadConfiguration
			}

			// Create a new Basic Provider
			basicProvider, err := buildBasicProvider(configuration.Basic)
			if err != nil {
				log.Error("Configuration for SSO, attribute providers is set to use the \"basic\" provider, but this provider can not be configured")
				return nil, common.ErrBadConfiguration
			}

			// Add it the list of providers
			ssoProviders = append(ssoProviders, basicProvider)

		} else if *providerName == "ldap" {

			// If no configuration
			if configuration.Basic == nil {
				log.Error("Configuration for SSO, attribute providers is set to use the \"ldap\" provider, but this provider is not defined in the configuration")
				return nil, common.ErrBadConfiguration
			}

			// Create a new Basic Provider
			ldapProvider, err := buildLdapProvider(*configuration.Ldap)
			if err != nil {
				log.Error("Configuration for SSO, attribute providers is set to use the \"ldap\" provider, but this provider can not be configured")
				return nil, common.ErrBadConfiguration
			}

			// Add it the list of providers
			ssoProviders = append(ssoProviders, ldapProvider)

		} else {
			log.Error("Configuration for SSO, attribute providers can only be \"basic\" or \"ldap\"")
			return nil, common.ErrBadConfiguration
		}
	}

	return ssoProviders, nil
}
