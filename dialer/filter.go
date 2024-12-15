package dialer

import (
	"context"
	"fmt"
	"net"
	"net/http"
)

type FilterFunc = func(ctx context.Context, req *http.Request, username, network, address string) error

type ErrAccessDenied struct {
	err error
}

func (e ErrAccessDenied) Error() string {
	return fmt.Sprintf("access denied: %v", e.err)
}

func (e ErrAccessDenied) Unwrap() error {
	return e.err
}

type filterContextKey struct{}

type filterContextParams struct {
	req      *http.Request
	username string
}

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
	req, username := FilterParamsFromContext(ctx)
	if ferr := f.f(ctx, req, username, network, address); ferr != nil {
		return nil, ErrAccessDenied{ferr}
	}
	return f.next.DialContext(ctx, network, address)
}

func (f FilterDialer) Dial(network, address string) (net.Conn, error) {
	panic("dialer tree linking issue: FilterDialer should never receive calls without context")
}

func (f FilterDialer) WantsHostname(ctx context.Context, network, address string) bool {
	return WantsHostname(ctx, network, address, f.next)
}

func FilterParamsFromContext(ctx context.Context) (*http.Request, string) {
	params := ctx.Value(filterContextKey{}).(filterContextParams)
	return params.req, params.username
}

func FilterParamsToContext(ctx context.Context, req *http.Request, username string) context.Context {
	return context.WithValue(ctx, filterContextKey{}, filterContextParams{req, username})
}

var _ Dialer = FilterDialer{}
var _ HostnameWanter = FilterDialer{}
