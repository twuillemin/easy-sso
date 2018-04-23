package easy_sso_client

// AuthenticationResponse defines the data returned when an Authentication/Refresh query is executed
// successfully
type AuthenticationResponse struct {
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// TokenRequestBody holds the information expected from the body of the GetToken query
type TokenRequestBody struct {
	UserName string `form:"username" binding:"required"`
	Password string `form:"password" binding:"required"`
}

// TokenRefreshBody holds the information expected from the body of the RefreshToken query
type TokenRefreshBody struct {
	RefreshToken string `form:"refresh_token" binding:"required"`
}
