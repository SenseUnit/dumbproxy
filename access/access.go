package access

import (
	"context"
	"net/http"
)

type Filter interface {
	Access(ctx context.Context, req *http.Request, username, network, address string) error
}
