package dialer

import (
	"context"
	"net"
	"net/http"

	"github.com/SenseUnit/dumbproxy/dialer/dto"
	"github.com/SenseUnit/dumbproxy/dialer/errors"
)

type FilterFunc = func(ctx context.Context, req *http.Request, username, network, address string) error

type FilterDialer struct {
	f    FilterFunc
	next Dialer
}

func NewFilterDialer(filterFunc FilterFunc, next Dialer) FilterDialer {
	return FilterDialer{
		f:    filterFunc,
		next: next,
	}
}

func (f FilterDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	req, username := dto.FilterParamsFromContext(ctx)
	if ferr := f.f(ctx, req, username, network, address); ferr != nil {
		return nil, errors.ErrAccessDenied{ferr}
	}
	return f.next.DialContext(ctx, network, address)
}

func (f FilterDialer) Dial(network, address string) (net.Conn, error) {
	panic("dialer tree linking issue: FilterDialer should never receive calls without context")
}

func (f FilterDialer) WantsHostname(ctx context.Context, network, address string) bool {
	return WantsHostname(ctx, network, address, f.next)
}

var _ Dialer = FilterDialer{}
var _ HostnameWanter = FilterDialer{}
