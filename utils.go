package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh/terminal"
	xproxy "golang.org/x/net/proxy"
)

const COPY_BUF = 128 * 1024

func proxy(ctx context.Context, left, right net.Conn) {
	wg := sync.WaitGroup{}
	cpy := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		dst.Close()
	}
	wg.Add(2)
	go cpy(left, right)
	go cpy(right, left)
	groupdone := make(chan struct{}, 1)
	go func() {
		wg.Wait()
		groupdone <- struct{}{}
	}()
	select {
	case <-ctx.Done():
		left.Close()
		right.Close()
	case <-groupdone:
		return
	}
	<-groupdone
	return
}

func proxyh2(ctx context.Context, leftreader io.ReadCloser, leftwriter io.Writer, right net.Conn) {
	wg := sync.WaitGroup{}
	ltr := func(dst net.Conn, src io.Reader) {
		defer wg.Done()
		io.Copy(dst, src)
		dst.Close()
	}
	rtl := func(dst io.Writer, src io.Reader) {
		defer wg.Done()
		copyBody(dst, src)
	}
	wg.Add(2)
	go ltr(right, leftreader)
	go rtl(leftwriter, right)
	groupdone := make(chan struct{}, 1)
	go func() {
		wg.Wait()
		groupdone <- struct{}{}
	}()
	select {
	case <-ctx.Done():
		leftreader.Close()
		right.Close()
	case <-groupdone:
		return
	}
	<-groupdone
	return
}

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Connection",
	"Proxy-Authorization",
	"Te", // canonicalized version of "TE"
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func delHopHeaders(header http.Header) {
	for _, h := range hopHeaders {
		header.Del(h)
	}
}

func hijack(hijackable interface{}) (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := hijackable.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("Connection doesn't support hijacking")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, nil, err
	}
	var emptytime time.Time
	err = conn.SetDeadline(emptytime)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	return conn, rw, nil
}

func flush(flusher interface{}) bool {
	f, ok := flusher.(http.Flusher)
	if !ok {
		return false
	}
	f.Flush()
	return true
}

func copyBody(wr io.Writer, body io.Reader) {
	buf := make([]byte, COPY_BUF)
	for {
		bread, read_err := body.Read(buf)
		var write_err error
		if bread > 0 {
			_, write_err = wr.Write(buf[:bread])
			flush(wr)
		}
		if read_err != nil || write_err != nil {
			break
		}
	}
}

func makeServerTLSConfig(certfile, keyfile, cafile, ciphers string, h2 bool) (*tls.Config, error) {
	var cfg tls.Config
	cert, err := tls.LoadX509KeyPair(certfile, keyfile)
	if err != nil {
		return nil, err
	}
	cfg.Certificates = []tls.Certificate{cert}
	if cafile != "" {
		roots := x509.NewCertPool()
		certs, err := ioutil.ReadFile(cafile)
		if err != nil {
			return nil, err
		}
		if ok := roots.AppendCertsFromPEM(certs); !ok {
			return nil, errors.New("Failed to load CA certificates")
		}
		cfg.ClientCAs = roots
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
	}
	cfg.CipherSuites = makeCipherList(ciphers)
	if h2 {
		cfg.NextProtos = []string{"h2", "http/1.1"}
	}
	return &cfg, nil
}

func updateServerTLSConfig(cfg *tls.Config, cafile, ciphers string, h2 bool) (*tls.Config, error) {
	if cafile != "" {
		roots := x509.NewCertPool()
		certs, err := ioutil.ReadFile(cafile)
		if err != nil {
			return nil, err
		}
		if ok := roots.AppendCertsFromPEM(certs); !ok {
			return nil, errors.New("Failed to load CA certificates")
		}
		cfg.ClientCAs = roots
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
	}
	cfg.CipherSuites = makeCipherList(ciphers)
	if h2 {
		cfg.NextProtos = []string{"h2", "http/1.1"}
	}
	return cfg, nil
}

func makeCipherList(ciphers string) []uint16 {
	if ciphers == "" {
		return nil
	}

	cipherIDs := make(map[string]uint16)
	for _, cipher := range tls.CipherSuites() {
		cipherIDs[cipher.Name] = cipher.ID
	}

	cipherNameList := strings.Split(ciphers, ":")
	cipherIDList := make([]uint16, 0, len(cipherNameList))

	for _, name := range cipherNameList {
		id, ok := cipherIDs[name]
		if !ok {
			log.Printf("WARNING: Unknown cipher \"%s\"", name)
		}
		cipherIDList = append(cipherIDList, id)
	}

	return cipherIDList
}

func list_ciphers() {
	for _, cipher := range tls.CipherSuites() {
		fmt.Println(cipher.Name)
	}
}

func passwd(filename string, cost int, args ...string) error {
	var (
		username, password, password2 string
		err                           error
	)

	if len(args) > 0 {
		username = args[0]
	} else {
		username, err = prompt("Enter username: ", false)
		if err != nil {
			return fmt.Errorf("can't get username: %w", err)
		}
	}

	if len(args) > 1 {
		password = args[1]
	} else {
		password, err = prompt("Enter password: ", true)
		if err != nil {
			return fmt.Errorf("can't get password: %w", err)
		}
		password2, err = prompt("Repeat password: ", true)
		if err != nil {
			return fmt.Errorf("can't get password (repeat): %w", err)
		}
		if password != password2 {
			return fmt.Errorf("passwords do not match")
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return fmt.Errorf("can't generate password hash: %w", err)
	}

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("can't open file: %w", err)
	}
	defer f.Close()

	_, err = f.WriteString(fmt.Sprintf("%s:%s\n", username, hash))
	if err != nil {
		return fmt.Errorf("can't write to file: %w", err)
	}

	return nil
}

func fileModTime(filename string) (time.Time, error) {
	f, err := os.Open(filename)
	if err != nil {
		return time.Time{}, fmt.Errorf("fileModTime(): can't open file %q: %w", filename, err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return time.Time{}, fmt.Errorf("fileModTime(): can't stat file %q: %w", filename, err)
	}

	return fi.ModTime(), nil
}

func prompt(prompt string, secure bool) (string, error) {
	var input string
	fmt.Print(prompt)

	if secure {
		b, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", err
		}
		input = string(b)
		fmt.Println()
	} else {
		fmt.Scanln(&input)
	}
	return input, nil
}

type Dialer xproxy.Dialer
type ContextDialer xproxy.ContextDialer

var registerDialerTypesOnce sync.Once

func proxyDialerFromURL(proxyURL string, forward Dialer) (Dialer, error) {
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
	return d, nil
}

type wrappedDialer struct {
	d Dialer
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

func maybeWrapWithContextDialer(d Dialer) ContextDialer {
	if xd, ok := d.(ContextDialer); ok {
		return xd
	}
	return wrappedDialer{d}
}
