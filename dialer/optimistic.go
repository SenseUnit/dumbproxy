package dialer

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	xproxy "golang.org/x/net/proxy"

	"github.com/SenseUnit/dumbproxy/tlsutil"
)

type OptimisticHTTPProxyDialer struct {
	address   string
	tlsConfig *tls.Config
	userinfo  *url.Userinfo
	next      Dialer
}

func NewOptimisticHTTPProxyDialer(address string, tlsConfig *tls.Config, userinfo *url.Userinfo, next LegacyDialer) *OptimisticHTTPProxyDialer {
	return &OptimisticHTTPProxyDialer{
		address:   address,
		tlsConfig: tlsConfig,
		next:      MaybeWrapWithContextDialer(next),
		userinfo:  userinfo,
	}
}

func OptimisticHTTPProxyDialerFromURL(u *url.URL, next xproxy.Dialer) (xproxy.Dialer, error) {
	host := u.Hostname()
	port := u.Port()

	var tlsConfig *tls.Config
	var err error
	switch strings.ToLower(u.Scheme) {
	case "http+optimistic":
		if port == "" {
			port = "80"
		}
	case "https+optimistic":
		if port == "" {
			port = "443"
		}
		tlsConfig, err = tlsutil.TLSConfigFromURL(u)
		if err != nil {
			return nil, fmt.Errorf("TLS configuration failed: %w", err)
		}
	default:
		return nil, errors.New("unsupported proxy type")
	}

	address := net.JoinHostPort(host, port)

	return NewOptimisticHTTPProxyDialer(address, tlsConfig, u.User, next), nil
}

func (d *OptimisticHTTPProxyDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *OptimisticHTTPProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, errors.New("only \"tcp\" network is supported")
	}
	conn, err := d.next.DialContext(ctx, "tcp", d.address)
	if err != nil {
		return nil, fmt.Errorf("proxy dialer is unable to make connection: %w", err)
	}
	if d.tlsConfig != nil {
		conn = tls.Client(conn, d.tlsConfig)
	}

	return &futureH1ProxiedConn{
		Conn:     conn,
		address:  address,
		userinfo: d.userinfo,
	}, nil
}

type futureH1ProxiedConn struct {
	net.Conn
	address  string
	userinfo *url.Userinfo
	rDone    bool
	wDone    bool
	rErr     error
	wErr     error
}

func (c *futureH1ProxiedConn) Write(b []byte) (n int, err error) {
	if c.wErr != nil {
		return 0, c.wErr
	}
	if !c.wDone {
		buf := new(bytes.Buffer)
		fmt.Fprintf(buf, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", c.address, c.address)
		if c.userinfo != nil {
			fmt.Fprintf(buf, "Proxy-Authorization: %s\r\n", basicAuthHeader(c.userinfo))
		}
		fmt.Fprintf(buf, "User-Agent: dumbproxy\r\n\r\n")
		prologueBytes := buf.Len()
		buf.Write(b)
		n, err := c.Conn.Write(buf.Bytes())
		if err != nil {
			c.wErr = err
		}
		c.wDone = true
		c.address = ""
		c.userinfo = nil
		return max(0, n-prologueBytes), err
	}
	return c.Conn.Write(b)
}

func (c *futureH1ProxiedConn) Read(b []byte) (n int, err error) {
	if c.rErr != nil {
		return 0, c.rErr
	}
	if !c.rDone {
		resp, err := readResponse(c.Conn)
		if err != nil {
			c.rErr = fmt.Errorf("reading proxy response failed: %w", err)
			return 0, c.rErr
		}
		if resp.StatusCode != http.StatusOK {
			c.rErr = fmt.Errorf("bad status code from proxy: %d", resp.StatusCode)
			return 0, c.rErr
		}
		c.rDone = true
	}
	return c.Conn.Read(b)
}
