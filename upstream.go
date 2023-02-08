package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	xproxy "golang.org/x/net/proxy"
)

type HTTPProxyDialer struct {
	address  string
	tls      bool
	userinfo *url.Userinfo
	next     ContextDialer
}

func NewHTTPProxyDialer(address string, tls bool, userinfo *url.Userinfo, next Dialer) *HTTPProxyDialer {
	return &HTTPProxyDialer{
		address:  address,
		tls:      tls,
		next:     maybeWrapWithContextDialer(next),
		userinfo: userinfo,
	}
}

func HTTPProxyDialerFromURL(u *url.URL, next xproxy.Dialer) (xproxy.Dialer, error) {
	host := u.Hostname()
	port := u.Port()
	tls := false

	switch strings.ToLower(u.Scheme) {
	case "http":
		if port == "" {
			port = "80"
		}
	case "https":
		tls = true
		if port == "" {
			port = "443"
		}
	default:
		return nil, errors.New("unsupported proxy type")
	}

	address := net.JoinHostPort(host, port)

	return NewHTTPProxyDialer(address, tls, u.User, next), nil
}

func (d *HTTPProxyDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *HTTPProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, errors.New("only \"tcp\" network is supported")
	}
	conn, err := d.next.DialContext(ctx, "tcp", d.address)
	if err != nil {
		return nil, fmt.Errorf("proxy dialer is unable to make connection: %w", err)
	}
	if d.tls {
		hostname, _, err := net.SplitHostPort(d.address)
		if err != nil {
			hostname = address
		}
		conn = tls.Client(conn, &tls.Config{
			ServerName: hostname,
		})
	}

	stopGuardEvent := make(chan struct{})
	guardErr := make(chan error, 1)
	go func() {
		select {
		case <-stopGuardEvent:
			close(guardErr)
		case <-ctx.Done():
			conn.Close()
			guardErr <- ctx.Err()
		}
	}()
	var stopGuardOnce sync.Once
	stopGuard := func() {
		stopGuardOnce.Do(func() {
			close(stopGuardEvent)
		})
	}
	defer stopGuard()

	var reqBuf bytes.Buffer
	fmt.Fprintf(&reqBuf, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", address, address)
	if d.userinfo != nil {
		fmt.Fprintf(&reqBuf, "Proxy-Authorization: %s\r\n", basicAuthHeader(d.userinfo))
	}
	fmt.Fprintf(&reqBuf, "User-Agent: dumbproxy/%s\r\n\r\n", version)
	_, err = io.Copy(conn, &reqBuf)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("unable to write proxy request for remote connection: %w", err)
	}

	resp, err := readResponse(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("reading proxy response failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("bad status code from proxy: %d", resp.StatusCode)
	}

	stopGuard()
	if err := <-guardErr; err != nil {
		return nil, fmt.Errorf("context error: %w", err)
	}
	return conn, nil
}

var (
	responseTerminator = []byte("\r\n\r\n")
)

func readResponse(r io.Reader) (*http.Response, error) {
	var respBuf bytes.Buffer
	b := make([]byte, 1)
	for !bytes.HasSuffix(respBuf.Bytes(), responseTerminator) {
		n, err := r.Read(b)
		if err != nil {
			return nil, fmt.Errorf("unable to read HTTP response: %w", err)
		}
		if n == 0 {
			continue
		}
		_, err = respBuf.Write(b)
		if err != nil {
			return nil, fmt.Errorf("unable to store byte into buffer: %w", err)
		}
	}
	resp, err := http.ReadResponse(bufio.NewReader(&respBuf), nil)
	if err != nil {
		return nil, fmt.Errorf("unable to decode proxy response: %w", err)
	}
	return resp, nil
}

func basicAuthHeader(userinfo *url.Userinfo) string {
	username := userinfo.Username()
	password, _ := userinfo.Password()
	return "Basic " + base64.StdEncoding.EncodeToString(
		[]byte(username+":"+password))
}
