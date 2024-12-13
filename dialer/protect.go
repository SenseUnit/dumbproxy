package dialer

import (
	"context"
	"net"
)

type HostnameWanter interface {
	WantsHostname(ctx context.Context, net, address string) bool
}

type WrappedHostnameDialer struct {
	Dialer Dialer
}

func AlwaysRequireHostname(d Dialer) Dialer {
	return WrappedHostnameDialer{
		Dialer: d,
	}
}

func (w WrappedHostnameDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return w.Dialer.DialContext(ctx, network, address)
}

func (w WrappedHostnameDialer) Dial(network, address string) (net.Conn, error) {
	return w.Dialer.Dial(network, address)
}

func (w WrappedHostnameDialer) WantsHostname(_ context.Context, _, _ string) bool {
	return true
}

var _ Dialer = WrappedHostnameDialer{}
var _ HostnameWanter = WrappedHostnameDialer{}

func WantsHostname(ctx context.Context, net, address string, d Dialer) bool {
	if w, ok := d.(HostnameWanter); ok {
		return w.WantsHostname(ctx, net, address)
	}
	return false
}
