package access

import (
	"context"
	"net/http"
)

type Filter interface {
	Access(ctx context.Context, req *http.Request, username, network, address string) error
}

type AlwaysAllow struct{}

func (_ AlwaysAllow) Access(_ context.Context, _ *http.Request, _, _, _ string) error {
	return nil
}
