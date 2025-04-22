package dialer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/SenseUnit/dumbproxy/tlsutil"
	"golang.org/x/net/http2"
	xproxy "golang.org/x/net/proxy"
)

type H2ProxyDialer struct {
	address   string
	tlsConfig *tls.Config
	userinfo  *url.Userinfo
	next      Dialer
	t         *http2.Transport
}

func H2ProxyDialerFromURL(u *url.URL, next xproxy.Dialer) (xproxy.Dialer, error) {
	host := u.Hostname()
	port := u.Port()

	var (
		tlsConfig *tls.Config
		err       error
		h2c       bool
	)
	switch strings.ToLower(u.Scheme) {
	case "h2c":
		if port == "" {
			port = "80"
		}
		h2c = true
	case "h2":
		if port == "" {
			port = "443"
		}
		tlsConfig, err = tlsutil.TLSConfigFromURL(u)
		if !slices.Contains(tlsConfig.NextProtos, "h2") {
			tlsConfig.NextProtos = append([]string{"h2"}, tlsConfig.NextProtos...)
		}
		if err != nil {
			return nil, fmt.Errorf("TLS configuration failed: %w", err)
		}
	default:
		return nil, errors.New("unsupported proxy type")
	}

	address := net.JoinHostPort(host, port)
	t := &http2.Transport{
		AllowHTTP:       h2c,
		TLSClientConfig: tlsConfig,
	}
	nextDialer := MaybeWrapWithContextDialer(next)
	if h2c {
		t.DialTLSContext = func(ctx context.Context, network, _ string, _ *tls.Config) (net.Conn, error) {
			return nextDialer.DialContext(ctx, network, address)
		}
	} else {
		t.DialTLSContext = func(ctx context.Context, network, _ string, _ *tls.Config) (net.Conn, error) {
			conn, err := nextDialer.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			conn = tls.Client(conn, tlsConfig)
			return conn, nil
		}
	}

	return &H2ProxyDialer{
		address:   address,
		tlsConfig: tlsConfig,
		userinfo:  u.User,
		next:      MaybeWrapWithContextDialer(next),
		t:         t,
	}, nil
}

func (d *H2ProxyDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *H2ProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	h2c := d.tlsConfig == nil
	scheme := "https"
	if h2c {
		scheme = "http"
	}
	pr, pw := io.Pipe()
	connCtx, connCl := context.WithCancel(ctx)
	req := (&http.Request{
		Method: "CONNECT",
		URL: &url.URL{
			Scheme: scheme,
			Host:   address,
		},
		Header: http.Header{
			"User-Agent": []string{"dumbproxy"},
		},
		Body: pr,
		Host: address,
	}).WithContext(connCtx)
	if d.userinfo != nil {
		req.Header.Set("Proxy-Authorization", basicAuthHeader(d.userinfo))
	}
	resp, err := d.t.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		pw.Close()
		return nil, errors.New(resp.Status)
	}
	return &h2Conn{
		r:  resp.Body,
		w:  pw,
		cl: connCl,
	}, nil
}

type h2Conn struct {
	r  io.ReadCloser
	w  io.WriteCloser
	cl func()
}

func (c *h2Conn) Read(b []byte) (n int, err error) {
	return c.r.Read(b)
}

func (c *h2Conn) Write(b []byte) (n int, err error) {
	return c.w.Write(b)
}

func (c *h2Conn) Close() (err error) {
	defer c.cl()
	return errors.Join(c.w.Close(), c.r.Close())
}

func (c *h2Conn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

func (c *h2Conn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

func (c *h2Conn) SetDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "h2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *h2Conn) SetReadDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "h2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *h2Conn) SetWriteDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "h2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *h2Conn) CloseWrite() error {
	return c.w.Close()
}
