package server

import (
	"bitbucket.org/twuillemin/easy-sso/pkg/common"
	log "github.com/sirupsen/logrus"
)

// basicProvider is the structure holding all the information for a basic authentication provider
type basicProvider struct {
	users map[string]*basicUserInfo
}

// basicUserInfo is the structure holding all the information about a single user
type basicUserInfo struct {
	password string
	roles    []string
}

func (provider basicProvider) Authenticate(userName string, password string) (*authenticatedUser, error) {

	userInfo := provider.users[userName]
	if userInfo == nil {
		return nil, common.ErrUserNotFound
	}

	if password != userInfo.password {
		return nil, common.ErrUnauthorized
	}

	return &authenticatedUser{
		UserName: userName,
		Roles:    userInfo.roles,
	}, nil
}

func buildBasicProvider(configuration *BasicProviderConfiguration) (authenticationProvider, error) {

	if configuration == nil {
		log.Error("buildBasicProvider : parameter configuration was given null")
		return nil, common.ErrBadConfiguration
	}

	users := make(map[string]*basicUserInfo)

	// For all users found in the configuration
	for _, basicProviderUserConfig := range *configuration.Users {
		if basicProviderUserConfig == nil {
			log.Warn("Configuration for Basic, attribute users has a null entry. Skipping user.")
			continue
		}
		if (basicProviderUserConfig.UserName == nil) || (len(*basicProviderUserConfig.UserName) == 0) {
			log.Warn("Configuration for Basic, attribute users has an entry with an empty/null value for userName. Skipping user.")
			continue
		}

		// Filter null password to blank string
		var passwordToUse = ""
		if basicProviderUserConfig.Password != nil {
			passwordToUse = *basicProviderUserConfig.Password
		}

		var roles []string

		if basicProviderUserConfig.Roles == nil {
			roles = make([]string, 0, 0)
		} else {
			roles = make([]string, 0, len(*basicProviderUserConfig.Roles))
			for _, role := range *basicProviderUserConfig.Roles {
				if role == nil {
					log.Warn("Configuration for Basic, attribute users has an entry with a null value for role. Skipping role.")
					continue
				}
				roles = append(roles, *role)
			}
		}

		users[*basicProviderUserConfig.UserName] = &basicUserInfo{
			password: passwordToUse,
			roles:    roles,
		}
	}

	return basicProvider{
		users: users,
	}, nil
}
