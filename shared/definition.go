package easy_sso_client

import "github.com/dgrijalva/jwt-go"

// AuthenticationResponse defines the data returned when an Authentication/Refresh query is executed
// successfully
type AuthenticationResponse struct {
	TokenType    string `json:"tokenType"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

// TokenRequestBody holds the information expected from the body of the GetToken query
type TokenRequestBody struct {
	UserName string `form:"userName" binding:"required"`
	Password string `form:"password" binding:"required"`
}

// TokenRefreshBody holds the information expected from the body of the RefreshToken query
type TokenRefreshBody struct {
	RefreshToken string `form:"refreshToken" binding:"required"`
}

// CustomClaims holds the claims that will be transmitted with the token
type CustomClaims struct {
	User  string   `json:"user"`
	Roles []string `json:"roles"`
	jwt.StandardClaims
}
