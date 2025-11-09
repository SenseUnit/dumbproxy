package dialer

import (
	"context"
	"net"
)

type HostnameWanter interface {
	WantsHostname(ctx context.Context, net, address string) bool
}

type WrappedHostnameDialer struct {
	Dialer             Dialer
	WantsHostnameValue bool
}

func AlwaysRequireHostname(d Dialer) Dialer {
	return WrappedHostnameDialer{
		Dialer:             d,
		WantsHostnameValue: true,
	}
}

func NeverRequireHostname(d Dialer) Dialer {
	return WrappedHostnameDialer{
		Dialer:             d,
		WantsHostnameValue: false,
	}
}

func (w WrappedHostnameDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return w.Dialer.DialContext(ctx, network, address)
}

func (w WrappedHostnameDialer) Dial(network, address string) (net.Conn, error) {
	return w.Dialer.Dial(network, address)
}

func (w WrappedHostnameDialer) WantsHostname(_ context.Context, _, _ string) bool {
	return w.WantsHostnameValue
}

var _ Dialer = WrappedHostnameDialer{}
var _ HostnameWanter = WrappedHostnameDialer{}

func WantsHostname(ctx context.Context, net, address string, d Dialer) bool {
	if w, ok := d.(HostnameWanter); ok {
		return w.WantsHostname(ctx, net, address)
	}
	return false
}

func MaybeWrapWithHostnameWanter(d Dialer) Dialer {
	if _, ok := d.(HostnameWanter); ok {
		return d
	}
	return AlwaysRequireHostname(d)
}
