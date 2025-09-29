package dialer

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/url"
	"strconv"
	"strings"

	xproxy "golang.org/x/net/proxy"
)

func init() {
	xproxy.RegisterDialerType("http", HTTPProxyDialerFromURL)
	xproxy.RegisterDialerType("https", HTTPProxyDialerFromURL)
	xproxy.RegisterDialerType("http+optimistic", OptimisticHTTPProxyDialerFromURL)
	xproxy.RegisterDialerType("https+optimistic", OptimisticHTTPProxyDialerFromURL)
	xproxy.RegisterDialerType("h2", H2ProxyDialerFromURL)
	xproxy.RegisterDialerType("h2c", H2ProxyDialerFromURL)
	xproxy.RegisterDialerType("set-src-hints", NewHintsSettingDialerFromURL)
	xproxy.RegisterDialerType("cached", GetCachedDialer)
	xproxy.RegisterDialerType("socks5s", SOCKS5SDialerFromURL)
	xproxy.RegisterDialerType("socks5hs", SOCKS5SDialerFromURL)
}

type LegacyDialer interface {
	Dial(network, address string) (net.Conn, error)
}

type Dialer interface {
	LegacyDialer
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

func ProxyDialerFromURL(proxyURL string, forward Dialer) (Dialer, error) {
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

func MaybeWrapWithContextDialer(d LegacyDialer) Dialer {
	if xd, ok := d.(Dialer); ok {
		return xd
	}
	return wrappedDialer{d}
}

func garbageLenFuncFromURL(u *url.URL, paramname string) (func() int, error) {
	params, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("garbage len param parse failed: %w", err)
	}
	if !params.Has(paramname) {
		return nil, nil
	}
	left, right, found := strings.Cut(params.Get(paramname), "-")
	if found {
		lo, err := strconv.Atoi(left)
		if err != nil {
			return nil, fmt.Errorf("can't convert lower boundary for garbage length %q to int: %w", left, err)
		}
		if lo < 0 {
			return nil, errors.New("negative lower boundary for garbage length is not allowed")
		}
		hi, err := strconv.Atoi(right)
		if err != nil {
			return nil, fmt.Errorf("can't convert upper boundary for garbage length %q to int: %w", right, err)
		}
		if hi < 0 {
			return nil, errors.New("negative upper boundary for garbage length is not allowed")
		}
		if hi < lo {
			hi, lo = lo, hi
		}
		if hi == lo {
			return func() int {
				return lo
			}, nil
		}
		return func() int {
			return lo + rand.IntN(hi-lo)
		}, nil
	}
	l, err := strconv.Atoi(left)
	if err != nil {
		return nil, fmt.Errorf("can't convert garbage length %q to int: %w", left, err)
	}
	if l < 0 {
		return nil, errors.New("negative garbage length is not allowed")
	}
	return func() int {
		return l
	}, nil
}
