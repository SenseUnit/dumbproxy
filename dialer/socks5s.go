package dialer

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"

	"github.com/SenseUnit/dumbproxy/tlsutil"
	xproxy "golang.org/x/net/proxy"
)

func SOCKS5SDialerFromURL(u *url.URL, next xproxy.Dialer) (xproxy.Dialer, error) {
	var (
		tlsConfig  *tls.Config
		tlsFactory func(net.Conn, *tls.Config) net.Conn
		err        error
	)
	tlsConfig, err = tlsutil.TLSConfigFromURL(u)
	if err != nil {
		return nil, fmt.Errorf("TLS configuration failed: %w", err)
	}
	tlsFactory, err = tlsutil.TLSFactoryFromURL(u)
	if err != nil {
		return nil, fmt.Errorf("TLS configuration failed: %w", err)
	}
	u.Scheme = "socks5"
	u.RawQuery = ""
	return xproxy.FromURL(u, NewTLSWrappingDialer(tlsConfig, tlsFactory, MaybeWrapWithContextDialer(next)))
}

type TLSWrappingDialer struct {
	next       Dialer
	tlsConfig  *tls.Config
	tlsFactory func(net.Conn, *tls.Config) net.Conn
}

func NewTLSWrappingDialer(tlsConfig *tls.Config, tlsFactory func(net.Conn, *tls.Config) net.Conn, next Dialer) *TLSWrappingDialer {
	return &TLSWrappingDialer{
		next:       next,
		tlsConfig:  tlsConfig,
		tlsFactory: tlsFactory,
	}
}

func (d *TLSWrappingDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *TLSWrappingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.next.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return d.tlsFactory(conn, d.tlsConfig), nil
}
