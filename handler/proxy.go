package handler

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"time"
)

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

func wrapPendingWrite(data []byte, c net.Conn) *pendingWriteConn {
	return &pendingWriteConn{
		data: data,
		Conn: c,
	}
}

type pendingWriteConn struct {
	net.Conn
	data []byte
	done bool
	wErr error
}

func (p *pendingWriteConn) Write(b []byte) (n int, err error) {
	if p.wErr != nil {
		return 0, p.wErr
	}
	if !p.done {
		buf := append(append(make([]byte, 0, len(p.data)+len(b)), p.data...), b...)
		n, err := p.Conn.Write(buf)
		if err != nil {
			p.wErr = err
		}
		n = max(0, n-len(p.data))
		p.done = true
		p.data = nil
		return n, err
	}
	return p.Conn.Write(b)
}
