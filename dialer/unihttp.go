package dialer

import (
	"context"
	"errors"
	"net"
	"net/url"

	xproxy "golang.org/x/net/proxy"
)

type UnifiedHTTPSProxyDialer struct {
	h2dialer Dialer
	h1dialer Dialer
}

func UnifiedHTTPSProxyDialerFromURL(u *url.URL, d xproxy.Dialer) (xproxy.Dialer, error) {
	h2, err := H2ProxyDialerFromURL(u, d)
	if err != nil {
		return nil, err
	}
	h1, err := H1ProxyDialerFromURL(u, d)
	if err != nil {
		return nil, err
	}
	return &UnifiedHTTPSProxyDialer{
		h2dialer: MaybeWrapWithContextDialer(h2),
		h1dialer: MaybeWrapWithContextDialer(h1),
	}, nil
}

func (d *UnifiedHTTPSProxyDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *UnifiedHTTPSProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.h2dialer.DialContext(ctx, network, address)
	if err != nil {
		if rerr, ok := errors.AsType[h1RedeemError](err); ok {
			// we've got a connection, but need it's HTTP/1
			ctx = redeemedConnToContext(ctx, rerr.conn)
			conn, err := d.h1dialer.DialContext(ctx, network, address)
			if err != nil {
				// early cleanup
				rerr.Close()
			}
			return conn, err
		}
	}
	return conn, err
}
