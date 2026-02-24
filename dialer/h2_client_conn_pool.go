// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file (see https://cs.opensource.google/go/x/net/+/refs/tags/v0.43.0:LICENSE).

// Transport code's client connection pooling.

package dialer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"
)

type clientConnPool struct {
	t *http2.Transport

	mu          sync.Mutex
	conns       []*http2.ClientConn
	dialing     *dialCall    // currently in-flight dial
	addConnCall *addConnCall // in-flight addConnIfNeeded calls
	prepare     func(context.Context, *http2.ClientConn) (*http2.ClientConn, error)
}

func (p *clientConnPool) GetClientConn(req *http.Request, addr string) (*http2.ClientConn, error) {
	return p.getClientConn(req, addr, dialOnMiss)
}

const (
	dialOnMiss   = true
	noDialOnMiss = false
)

// isConnectionCloseRequest reports whether req should use its own
// connection for a single request and then close the connection.
func isConnectionCloseRequest(req *http.Request) bool {
	return req.Close || httpguts.HeaderValuesContainsToken(req.Header["Connection"], "close")
}

func strSliceContains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func (p *clientConnPool) newTLSConfig(host string) *tls.Config {
	cfg := new(tls.Config)
	if p.t.TLSClientConfig != nil {
		*cfg = *p.t.TLSClientConfig.Clone()
	}
	if !strSliceContains(cfg.NextProtos, http2.NextProtoTLS) {
		cfg.NextProtos = append([]string{http2.NextProtoTLS}, cfg.NextProtos...)
	}
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	return cfg
}

func (p *clientConnPool) dialClientConn(ctx context.Context, addr string) (*http2.ClientConn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	tconn, err := p.dialTLS(ctx, "tcp", addr, p.newTLSConfig(host))
	if err != nil {
		return nil, err
	}
	cc, err := p.t.NewClientConn(tconn)
	if err != nil {
		return nil, err
	}
	if p.prepare != nil {
		return p.prepare(ctx, cc)
	}
	return cc, nil
}

func (p *clientConnPool) dialTLS(ctx context.Context, network, addr string, tlsCfg *tls.Config) (net.Conn, error) {
	if p.t.DialTLSContext != nil {
		return p.t.DialTLSContext(ctx, network, addr, tlsCfg)
	} else if p.t.DialTLS != nil {
		return p.t.DialTLS(network, addr, tlsCfg)
	}

	tlsCn, err := dialTLSWithContext(ctx, network, addr, tlsCfg)
	if err != nil {
		return nil, err
	}
	state := tlsCn.ConnectionState()
	if p := state.NegotiatedProtocol; p != http2.NextProtoTLS {
		return nil, fmt.Errorf("http2: unexpected ALPN protocol %q; want %q", p, http2.NextProtoTLS)
	}
	if !state.NegotiatedProtocolIsMutual {
		return nil, errors.New("http2: could not negotiate protocol mutually")
	}
	return tlsCn, nil
}

func dialTLSWithContext(ctx context.Context, network, addr string, cfg *tls.Config) (*tls.Conn, error) {
	dialer := &tls.Dialer{
		Config: cfg,
	}
	cn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	tlsCn := cn.(*tls.Conn) // DialContext comment promises this will always succeed
	return tlsCn, nil
}

func (p *clientConnPool) getClientConn(req *http.Request, addr string, dialOnMiss bool) (*http2.ClientConn, error) {
	// TODO(dneil): Dial a new connection when t.DisableKeepAlives is set?
	if isConnectionCloseRequest(req) && dialOnMiss {
		// It gets its own connection.
		cc, err := p.dialClientConn(req.Context(), addr)
		if err != nil {
			return nil, err
		}
		return cc, nil
	}
	for {
		p.mu.Lock()
		for _, cc := range p.conns {
			if cc.ReserveNewRequest() {
				p.mu.Unlock()
				return cc, nil
			}
		}
		if !dialOnMiss {
			p.mu.Unlock()
			return nil, http2.ErrNoCachedConn
		}
		call := p.getStartDialLocked(req.Context(), addr)
		p.mu.Unlock()
		<-call.done
		if shouldRetryDial(call, req) {
			continue
		}
		cc, err := call.res, call.err
		if err != nil {
			return nil, err
		}
		if cc.ReserveNewRequest() {
			return cc, nil
		}
	}
}

// incomparable is a zero-width, non-comparable type. Adding it to a struct
// makes that struct also non-comparable, and generally doesn't add
// any size (as long as it's first).
type incomparable [0]func()

// dialCall is an in-flight Transport dial call to a host.
type dialCall struct {
	_ incomparable
	p *clientConnPool
	// the context associated with the request
	// that created this dialCall
	ctx  context.Context
	done chan struct{}     // closed when done
	res  *http2.ClientConn // valid after done is closed
	err  error             // valid after done is closed
}

// requires p.mu is held.
func (p *clientConnPool) getStartDialLocked(ctx context.Context, addr string) *dialCall {
	if call := p.dialing; call != nil {
		// A dial is already in-flight. Don't start another.
		return call
	}
	call := &dialCall{p: p, done: make(chan struct{}), ctx: ctx}
	p.dialing = call
	go call.dial(call.ctx, addr)
	return call
}

// run in its own goroutine.
func (c *dialCall) dial(ctx context.Context, addr string) {
	c.res, c.err = c.p.dialClientConn(ctx, addr)

	c.p.mu.Lock()
	c.p.dialing = nil
	if c.err == nil {
		c.p.addConnLocked(addr, c.res)
	}
	c.p.mu.Unlock()

	close(c.done)
}

// addConnIfNeeded makes a NewClientConn out of c if a connection for key doesn't
// already exist. It coalesces concurrent calls with the same key.
// This is used by the http1 Transport code when it creates a new connection. Because
// the http1 Transport doesn't de-dup TCP dials to outbound hosts (because it doesn't know
// the protocol), it can get into a situation where it has multiple TLS connections.
// This code decides which ones live or die.
// The return value used is whether c was used.
// c is never closed.
func (p *clientConnPool) addConnIfNeeded(key string, t *http2.Transport, c net.Conn) (used bool, err error) {
	p.mu.Lock()
	for _, cc := range p.conns {
		if cc.CanTakeNewRequest() {
			p.mu.Unlock()
			return false, nil
		}
	}
	call := p.addConnCall
	dup := call != nil
	if !dup {
		call = &addConnCall{
			p:    p,
			done: make(chan struct{}),
		}
		p.addConnCall = call
		go call.run(t, key, c)
	}
	p.mu.Unlock()

	<-call.done
	if call.err != nil {
		return false, call.err
	}
	return !dup, nil
}

type addConnCall struct {
	_    incomparable
	p    *clientConnPool
	done chan struct{} // closed when done
	err  error
}

func (c *addConnCall) run(t *http2.Transport, key string, nc net.Conn) {
	cc, err := t.NewClientConn(nc)

	p := c.p
	p.mu.Lock()
	if err != nil {
		c.err = err
	} else {
		p.addConnLocked(key, cc)
	}
	p.addConnCall = nil
	p.mu.Unlock()
	close(c.done)
}

// p.mu must be held
func (p *clientConnPool) addConnLocked(key string, cc *http2.ClientConn) {
	for _, v := range p.conns {
		if v == cc {
			return
		}
	}
	p.conns = append(p.conns, cc)
}

func (p *clientConnPool) MarkDead(cc *http2.ClientConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.conns = filterOutClientConn(p.conns, cc)
}

func filterOutClientConn(in []*http2.ClientConn, exclude *http2.ClientConn) []*http2.ClientConn {
	out := in[:0]
	for _, v := range in {
		if v != exclude {
			out = append(out, v)
		}
	}
	// If we filtered it out, zero out the last item to prevent
	// the GC from seeing it.
	if len(in) != len(out) {
		in[len(in)-1] = nil
	}
	return out
}

// shouldRetryDial reports whether the current request should
// retry dialing after the call finished unsuccessfully, for example
// if the dial was canceled because of a context cancellation or
// deadline expiry.
func shouldRetryDial(call *dialCall, req *http.Request) bool {
	if call.err == nil {
		// No error, no need to retry
		return false
	}
	if call.ctx == req.Context() {
		// If the call has the same context as the request, the dial
		// should not be retried, since any cancellation will have come
		// from this request.
		return false
	}
	if !errors.Is(call.err, context.Canceled) && !errors.Is(call.err, context.DeadlineExceeded) {
		// If the call error is not because of a context cancellation or a deadline expiry,
		// the dial should not be retried.
		return false
	}
	// Only retry if the error is a context cancellation error or deadline expiry
	// and the context associated with the call was canceled or expired.
	return call.ctx.Err() != nil
}
