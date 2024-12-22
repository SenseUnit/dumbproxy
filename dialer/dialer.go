package dialer

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"

	xproxy "golang.org/x/net/proxy"
)

type LegacyDialer interface {
	Dial(network, address string) (net.Conn, error)
}

type Dialer interface {
	LegacyDialer
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

var registerDialerTypesOnce sync.Once

func ProxyDialerFromURL(proxyURL string, forward Dialer) (Dialer, error) {
	registerDialerTypesOnce.Do(func() {
		xproxy.RegisterDialerType("http", HTTPProxyDialerFromURL)
		xproxy.RegisterDialerType("https", HTTPProxyDialerFromURL)
	})
	parsedURL, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("unable to parse proxy URL: %w", err)
	}
	d, err := xproxy.FromURL(parsedURL, forward)
	if err != nil {
		return nil, fmt.Errorf("unable to construct proxy dialer from URL %q: %w", proxyURL, err)
	}
	return MaybeWrapWithHostnameWanter(MaybeWrapWithContextDialer(d)), nil
}

type wrappedDialer struct {
	d LegacyDialer
}

func (wd wrappedDialer) Dial(net, address string) (net.Conn, error) {
	return wd.d.Dial(net, address)
}

func (wd wrappedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var (
		conn net.Conn
		done = make(chan struct{}, 1)
		err  error
	)
	go func() {
		conn, err = wd.d.Dial(network, address)
		close(done)
		if conn != nil && ctx.Err() != nil {
			conn.Close()
		}
	}()
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case <-done:
	}
	return conn, err
}

var _ HostnameWanter = new(BoundDialer)

func MaybeWrapWithContextDialer(d LegacyDialer) Dialer {
	if xd, ok := d.(Dialer); ok {
		return xd
	}
	return wrappedDialer{d}
}

func parseIPList(list string) ([]net.IP, error) {
	res := make([]net.IP, 0)
	for _, elem := range strings.Split(list, ",") {
		elem = strings.TrimSpace(elem)
		if len(elem) == 0 {
			continue
		}
		if parsed := net.ParseIP(elem); parsed == nil {
			return nil, fmt.Errorf("unable to parse IP address %q", elem)
		} else {
			res = append(res, parsed)
		}
	}
	return res, nil
}
