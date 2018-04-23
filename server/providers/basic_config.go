package providers

import (
	log "github.com/sirupsen/logrus"
)

type BasicProviderConfig struct {
	Users *[]*BasicProviderUserConfig `json:"users"`
}

type BasicProviderUserConfig struct {
	UserName *string    `json:"userName"`
	Password *string    `json:"password"`
	Roles    *[]*string `json:"roles"`
}

func readBasicConfiguration(configuration *BasicProviderConfig) (map[string]*basicUserInfo, error) {

	if configuration == nil {
		log.Error("Configuration for Basic is missing")
		return nil, ErrBadConfiguration
	}

	if configuration.Users == nil {
		log.Error("Configuration for Basic is missing the definition for users attribute")
		return nil, ErrBadConfiguration
	}

	users := make(map[string]*basicUserInfo)

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

	return users, nil
}
