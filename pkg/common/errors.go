package common

import "errors"

var (
	ErrUnauthorized           = errors.New("not Authorized")
	ErrUserNotFound           = errors.New("user Not Found")
	ErrBadConfiguration       = errors.New("the configuration is wrong")
	ErrRefreshTokenNotFound   = errors.New("the refresh token was not found in the HTTP query")
	ErrRefreshTooOld          = errors.New("the refresh token given was too old. Full connection is mandatory")
	ErrNoAuthorization        = errors.New("the HTTP query does not have a valid Authorization")
	ErrMalformedAuthorization = errors.New("the received Authorization in the HTTP query is malformed")
	ErrSignatureInvalid       = errors.New("the signature of the token in the HTTP query can not be verified")
	ErrTokenMalformed         = errors.New("the token in the HTTP query is too malformed")
	ErrTokenTooOld            = errors.New("the token in the HTTP query is too old")
	EmptyResponseFromServer   = errors.New("the response from the server was empty")
)
