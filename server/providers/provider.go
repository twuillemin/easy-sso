package providers

import "errors"

var (
	ErrUnauthorized     = errors.New("not Authorized")
	ErrUserNotFound     = errors.New("user Not Found")
	ErrBadConfiguration = errors.New("the configuration of the server is wrong")
)

type AuthenticatedUser struct {
	UserName string
	Roles    []string
}

// AuthenticationProvider is what it needs to be implemented for authentication functionality.
type AuthenticationProvider interface {
	// Auth takes user,password strings as arguments and returns the user, user roles (e.g providers groups)
	// (string slice) if the call succeeds. Auth should return the ErrUnAuthorized or ErrUserNotFound error if
	// auth fails or if the user is not found respectively.
	Authenticate(userName string, password string) (*AuthenticatedUser, error)
}
