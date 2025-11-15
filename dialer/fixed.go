package dialer

import (
	"context"
	"errors"
	"net"
	"net/url"

	xproxy "golang.org/x/net/proxy"
)

type FixedDstDialer struct {
	addr string
	next Dialer
}

func NewFixedDstDialerFromURL(u *url.URL, next xproxy.Dialer) (xproxy.Dialer, error) {
	host, port := u.Hostname(), u.Port()
	if host == "" {
		return nil, errors.New("missing hostname")
	}
	if port == "" {
		return nil, errors.New("missing port")
	}
	return &FixedDstDialer{
		addr: net.JoinHostPort(host, port),
		next: MaybeWrapWithContextDialer(next),
	}, nil
}

func (d *FixedDstDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *FixedDstDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.next.DialContext(ctx, network, d.addr)
}

func (d *FixedDstDialer) WantsHostname(_ context.Context, _, _ string) bool {
	// there is no point resolving address which we will discard anyway
	return true
}

var _ Dialer = new(FixedDstDialer)
var _ HostnameWanter = new(FixedDstDialer)
