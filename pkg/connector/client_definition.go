package connector

import (
	"net/http"
)

type Client interface {
	AuthenticateRequest(request *http.Request) error
}
