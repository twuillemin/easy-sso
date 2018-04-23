package providers

type basicUserInfo struct {
	password string
	roles    []string
}

type BasicProvider struct {
	users map[string]*basicUserInfo
}

func NewBasicProvider(configuration *BasicProviderConfig) (*BasicProvider, error) {

	users, err := readBasicConfiguration(configuration)
	if err != nil {
		return nil, err
	}

	return &BasicProvider{
		users: users,
	}, nil
}

func (provider BasicProvider) Authenticate(userName string, password string) (*AuthenticatedUser, error) {

	userInfo := provider.users[userName]
	if userInfo == nil {
		return nil, ErrUserNotFound
	}

	if password != userInfo.password {
		return nil, ErrUnauthorized
	}

	return &AuthenticatedUser{
		UserName: userName,
		Roles:    userInfo.roles,
	}, nil
}
