package providers

import (
	"crypto/tls"
	"fmt"
	"time"

	"gopkg.in/ldap.v2"
)

type LdapProvider struct {
	host         string
	port         int
	ssl          bool
	baseDN       string
	bindDN       string
	bindPassword string
}

func NewLdapProvider(configuration *LdapProviderConfig) (*LdapProvider, error) {

	err := readLdapConfiguration(configuration)
	if err != nil {
		return nil, err
	}

	return &LdapProvider{
		host:         *configuration.Host,
		port:         *configuration.Port,
		ssl:          *configuration.Ssl,
		baseDN:       *configuration.BaseDN,
		bindDN:       *configuration.BindDN,
		bindPassword: *configuration.BindPassword,
	}, nil
}

func (provider *LdapProvider) Authenticate(userName string, password string) (*AuthenticatedUser, error) {

	// Applies to Dial and DialTLS methods.
	ldap.DefaultTimeout = 20 * time.Second

	// Connect to the Ldap
	ldapConnection, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", provider.host, provider.port))
	if err != nil {
		return nil, err
	}
	defer ldapConnection.Close()

	// Reconnect with TLS if ssl is requested.
	if provider.ssl {
		err = ldapConnection.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return nil, err
		}
	}

	// First bind with a read only user
	if provider.bindDN != "" {
		err = ldapConnection.Bind(provider.bindDN, provider.bindPassword)
		if err != nil {
			return nil, err
		}
	}

	// Prepare a request with the given username (max: 30s)
	userSearchRequest := ldap.NewSearchRequest(
		provider.baseDN,
		// Sets a time limit of 30 secs
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		30,
		false,
		fmt.Sprintf("(&(objectClass=inetOrgPerson)(uid=%s))", userName),
		[]string{"dn"},
		nil,
	)

	// Search the user
	userSearchResult, err := ldapConnection.Search(userSearchRequest)
	if err != nil {
		return nil, err
	}

	// If not a single entry, give up
	if len(userSearchResult.Entries) != 1 {
		return nil, ErrUserNotFound
	}

	userDN := userSearchResult.Entries[0].DN

	// Bind as the user to verify the password
	err = ldapConnection.Bind(userDN, password)
	if err != nil {
		return nil, ErrUnauthorized
	}

	// Now find the group membership (max: 30s)
	groupsSearchRequest := ldap.NewSearchRequest(
		provider.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		30,
		false, // sets a time limit of 30 secs
		fmt.Sprintf("(&(objectClass=posixGroup)(memberUid=%s))", userName),
		[]string{"cn"},
		nil,
	)
	groupsSearchResult, err := ldapConnection.Search(groupsSearchRequest)
	if err != nil {
		return nil, err
	}

	groups := groupsSearchResult.Entries[0].GetAttributeValues("cn")

	return &AuthenticatedUser{
		UserName: userName,
		Roles:    groups,
	}, nil
}
