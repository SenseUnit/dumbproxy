package handler

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

const COPY_BUF = 128 * 1024

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

func copyAndCloseWrite(dst io.WriteCloser, src io.ReadCloser) error {
	_, err := io.Copy(dst, src)
	if closeWriter, ok := dst.(interface {
		CloseWrite() error
	}); ok {
		closeWriter.CloseWrite()
	} else {
		dst.Close()
	}
	return err
}

func futureCopyAndCloseWrite(c chan<- error, dst io.WriteCloser, src io.ReadCloser) {
	c <- copyAndCloseWrite(dst, src)
	close(c)
}

func PairConnections(ctx context.Context, username string, incoming, outgoing io.ReadWriteCloser) error {
	var err error
	i2oErr := make(chan error, 1)
	o2iErr := make(chan error, 1)
	ctxErr := ctx.Done()

	go futureCopyAndCloseWrite(i2oErr, outgoing, incoming)
	go futureCopyAndCloseWrite(o2iErr, incoming, outgoing)

	// do while we're listening to children channels
	for i2oErr != nil || o2iErr != nil {
		select {
		case e := <-i2oErr:
			if err == nil {
				err = e
			}
			i2oErr = nil // unsubscribe
		case e := <-o2iErr:
			if err == nil {
				err = e
			}
			o2iErr = nil // unsubscribe
		case <-ctxErr:
			if err == nil {
				err = ctx.Err()
			}
			ctxErr = nil // unsubscribe
			incoming.Close()
			outgoing.Close()
		}
	}

	return err
}
