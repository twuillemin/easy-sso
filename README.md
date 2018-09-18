# EasySSO
EasySSO is a simple, but nonetheless efficient go package to integrate a Single Sign-On in your application. EasySSO is compose of the following projects:

 * [easy-sso-common](https://bitbucket.org/twuillemin/easy-sso-common): the common definition and structures used by all the sub-projects
 * [easy-sso](https://bitbucket.org/twuillemin/easy-sso): the SSO server component that your currently browsing. Along with the server this project also include components for services (validating the query) and client (authenticating and connecting to the services). These components only rely on the Go default http.
 * [easy-sso-mux](https://bitbucket.org/twuillemin/easy-sso-mux): a middleware for the [gorilla/mux](https://github.com/gorilla/mux) router, validating client authentication.
 * [easy-sso-negroni](https://bitbucket.org/twuillemin/easy-sso-negroni): a middleware for the [Negroni](https://github.com/urfave/negroni) web middleware, validating client authentication.

# Usage of the SSO and Authentication schema
For a client, the authentication is a two step process:

 * Retrieving a JWT Token
 * Sending the token to the query

When the token will be expired, the client must the request a refreshed token.

## Obtaining a JWT Token and using it
For getting a JWT token, the client must connect to the server and send its credentials (user and password). The server will then validate its credentials and if correct will return to the client a JWT token to be send by the client to the services protected by the server and a Refresh.

### Requesting credentials
A **POST** request must be made to the endpoint `/token`. This request must have a body containing a JSON as:


```json
{
    "userName": "The_name_of_the _user",
    "password": "The_password_of_the_user"
}
```


Note: This structure is also defined in the easy-sso-common project, as `TokenRequestBody`.


The server will then validate the credentials. In case of success, the server will answer the following JSON structure:


```json
{
    "tokenType": "bearer",
    "accessToken": "A very long string that is a JWT signed token",
    "refreshToken": "A GUID for refreshing the token"
}
```

Note: 

* This structure is also defined in the easy-sso-common project, as `AuthenticationResponse`.
* the tokenType is always "bearer".

### Server authentication
The authentication server may require an additional authentication on its endpoint. This authentication is NOT the user authentication but a simple secret shared between the server and the clients, to avoid external clients trying to connect. As the full authentication process may be resources consuming, a lot of authentication request amy be used as a form of DOS.

Also the server should only allow connection in HTPPs, never with HTTP.
 
In this case the authentication is a simple Basic HTTP authentication. The (very!) simplified token retrieving code is so:

```go
func getToken(userName string, password string, serverClientId string, serverClientPassword string) string {
    // Prepare the content of the token query
    jsonRequest, _ := json.Marshal(
        common.TokenRequestBody{
            UserName: userName,
            Password: password,
        })

    // Prepare the query to retrieve the token
    requestGetToken, _ := http.NewRequest(
        "POST",
        "https://myserver/token",
        bytes.NewBuffer(jsonRequest))

    // Add the authentication to the server
    if len(serverClientId) > 0 {
        requestGetToken.SetBasicAuth(serverClientId, serverClientPassword)
    }

    // Add the ContentType
    requestGetToken.Header.Add("Content-Type", "application/json")

    // Make the query
    httpClient := &http.Client{}
    responseGetToken, _ := httpClient.Do(requestGetToken)
    defer responseGetToken.Body.Close()

    // Read the body of the response
    buf := new(bytes.Buffer)
    buf.ReadFrom(responseGetToken.Body)

    // Get the body of the query
    var response common.AuthenticationResponse
    json.Unmarshal(buf.Bytes(), &response)

    // Return the access token
    return response.AccessToken
}
```

A better version of this code (with error management and HTTPs configuration) is located in the package connector of the project. 

### Making query
Once a client has obtained the JWT token, it can start using it immediately. For using the token, it is enough to add it to the HTTP headers of the query. The name of the header must be "Authorization" and the value of the header the concatenation of "Bearer " with the token+ the token.

A simple Go example would be like:

```go
// Make a request for getting a service
request, _ := http.NewRequest(
    "GET",
    "http://myserver:8080/service",
    nil)

// Add the jwt in the query
request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenString))
```

As for the token retrieving, a better version of this code is located in the package connector of the project. In particular, the version of the package will take care of the expiration of the token. 

## Content of the token
The JWT token is a standard JWT, signed with the server private key (RSA-512). As every JWT token, it contains "claims". 
The main ones are:


 * Standard JWT claims
 
Name     | Human name  | Type   | Description
-------- | ----------- | ------ | ----------------------------------------------------------------------------------------------------
`aud`    | Audience    | string | Not used in the current version
`exp`    | ExpiresAt   | int    | a number representing the expiration date of the token expressed in seconds since 1st of January 1970
`jti`    | Id          | string | Not used in the current version
`iat`    | IssuedAt    | int    | a number representing the creation date of the token expressed in seconds since 1st of January 1970
`iss`    | Issuer      | string | always "EasySSO Server" - but may change in the future
`nbf`    | NotBefore   | int    | Not used in the current version
`sub`    | Subject     | string | Not used in the current version


 * EasySSO specific claims 
 
Name     | Human name  | Type                | Description
-------- | ----------- | ------------------- | ---------------------------------------------
`user`   | User        | string              | the name/id of the user as given in the query
`roles`  | Roles       | array of strings    | the roles/profiles of the user


The structure of the claim is defined in the easy-sso-common project, as `CustomClaims`.

## Refreshing authentication
As a good practice, the access token has a short life span, such as few minutes. As the whole authentication can be a lengthy process, the client is also provided an refresh token. This token can be used for requesting the server a new access token without re-authenticating. For retrieving a fresh access token, a **POST** request must be made to the endpoint `/refresh`. This request must have a body containing a JSON as:

```json
{
    "refreshToken": "The GUID for refreshing the token"
}
```

As for the authentication, the server will reply with:

```json
{
    "tokenType": "bearer",
    "accessToken": "A NEW very long string that is a JWT signed token",
    "refreshToken": "A NEW GUID for refreshing the token"
}
```
                                        
Notes: 

 * This structure is also defined in the easy-sso-common project, as `TokenRefreshBody`.
 * If the refresh request fail, a full authentication is necessary.
 * The refresh tokens should be one-time use for security reasons (not implemented - may change soon). 

Although it may seem convoluted at first sight, the use of a refresh token offers several advantages:

 * An access token may be re-used without even the client knowing it: send between services, etc. In case the access token falls in bad hands, the shorter its lifespan, the less damage done. On the contrary, the refresh token is not known by no  one except the authentication server and the client.
 * (not implemented currently) As the token owns all the user permissions, if these permissions are changed, it won't be reflected for the services receiving the query as long as the original access token is used

# Server configuration
The whole SSO server configuration is a JSON file. The file may be given as a parameter of the SSO server. If no file is given, the server will try to load a file named `config.json` located int current working directory.

The configuration is composed of two objects:

Name                   | Description
---------------------- | --------------------------------------------------------------------------------------------
`server`               | the general configuration of the HTTP server hosting the SSO service
`authserver`           | the configuration of the authentication / token provider service 

Example:

```json
{
    "server" : {...},
    "authserver" : {...}
}
```
 
## Configuration of the HTTP server
The configuration is composed of five attributes:

Name                   | Description
---------------------- | --------------------------------------------------------------------------------------------
`port`                 | the port on which the server is listening (mandatory)
`httpsCertificate`     | the name of the file with public HTTPs certificate for the server (optional)
`httpsCertificateKey`  | the name of the file with the private HTTPS certificate key for the server (optional)
`clientId`             | the client id to be used for protecting the server with HTTP Basic Authentication (optional)
`clientPassword`       | the password to be used for protecting the server with HTTP Basic Authentication (optional)

Example:

```json
"server" : {
    "port": 443,
    "httpsCertificate": "/tmp/sso/server_https_public_certificate.crt",
    "httpsCertificateKey": "/tmp/sso/server_https_secret_key.crt",
    "clientId": "the_basic_authentication_client_id",
    "clientPassword": "the_basic_authentication_password" 
}
```

## Configuration of the Token provider service
The configuration of the SSO is composed of three objects:

Name                   | Description
---------------------- | --------------------------------------------------------------------------------------------
`sso`                  | the general configuration of the SSO service
`ldap`                 | the configuration of the authentication on an external LDAP server (optional)
`basic`                | the configuration of the authentication with hard coded user. For testing purpose only (optional)

Example:

```json
"authserver" : {
    "sso": {...},
    "ldap": {...},
    "basic": {...}
}
```

### Configuration of the SSO
The configuration is composed of four attributes:

Name                   | Description
---------------------- | --------------------------------------------------------------------------------------------
`privateKeyPath`       | the name of the file with the key used to sign the tokens
`tokenSecondsToLive`   | the time to live of the access token in seconds
`refreshSecondsToLive` | the time to live of the refresh token in seconds
`providers`            | an array of string, giving the authentication providers to be used. Note that the order of the provider is respected.

Example:
 
```json
"sso" : {
    "privateKeyPath": "/tmp/sso/token_signing.key",
    "tokenSecondsToLive": 60,
    "refreshSecondsToLive": 600,
    "providers": ["basic", "ldap"]
}
```

### Configuration of the LDAP
The configuration is composed of the classical attributes for connecting to an LDAP

Example:
 
```json
"ldap" : {
    "host": "myldapserver.somewhere.com",
    "port": 636,
    "ssl": true,
    "baseDN": "dc=EXAMPLE,dc=COM",
    "bindDN": "dc=EXAMPLE,dc=COM",
    "bindPassword": "super secret password very long for connecting to LDAP"
}
```
    
### Configuration of the Basic (hard coded) authentication
This authentication is useful for testing purpose, but should probably not be used in production. The basic authentication is a list of user, each user having a role and a list of roles. 

Example:

```json
"basic" : {
    "users": [
        {
            "userName": "admin",
            "password": "admin_password",
            "roles": ["administrator"]
        },
        {
            "userName": "user",
            "password": "user_password",
            "roles": ["user"]
        }
    ]
}
```
    
## Other endpoints
The authentication server also offers two additional endpoints:

* `/status`: will return some status information about the server
* `/reload-sso-configuration`: will reload the server configuration without loosing the refresh token. This allows to quickly change the configuration without restarting the server.
 
These endpoints should not be publicly accessible!
    
# Integration of the authentication server
In the main application, the authentication server is integrated with the HTTP server. However, it is very possible to use the authentication server within you own environment.

The authentication server is created by giving it: 

* its configuration 
* a call-back method for loading a new configuration (optional - used by `/reload-sso-configuration`)
* two http handler (one for public endpoints, the other for private endpoints).
 
The configuration of the server is stored in a struct named `server.Configuration` with all the details given above. Once a configuration is assembled, simply calling `server.AddServer` is enough to have the authentication server added to the application. An example of such integration is given in the file `cmd/authserver/main.go`.

# License
Copyright 2018 Thomas Wuillemin

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
