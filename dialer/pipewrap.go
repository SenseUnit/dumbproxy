package dialer

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
)

type ReadPipe interface {
	io.Reader
	io.WriterTo
	io.Closer
	Fd() uintptr
	SetReadDeadline(t time.Time) error
}

type WritePipe interface {
	io.Writer
	io.ReaderFrom
	io.Closer
	Fd() uintptr
	SetWriteDeadline(t time.Time) error
}

type PipeAddr struct {
	rfd uintptr
	wfd uintptr
}

func (_ PipeAddr) Network() string {
	return "pipe"
}

func (a PipeAddr) String() string {
	return fmt.Sprintf("<read fd: %d, write rd: %d>", a.rfd, a.wfd)
}

type PipeConn struct {
	r  ReadPipe
	w  WritePipe
	rc sync.Once
	wc sync.Once
}

func NewPipeConn(r ReadPipe, w WritePipe) *PipeConn {
	return &PipeConn{
		r: r,
		w: w,
	}
}

func (c *PipeConn) Read(p []byte) (n int, err error) {
	return c.r.Read(p)
}

func (c *PipeConn) Write(p []byte) (n int, err error) {
	return c.w.Write(p)
}

func (c *PipeConn) Close() error {
	var err error
	if closeErr := c.CloseWrite(); closeErr != nil {
		err = multierror.Append(err, closeErr)
	}
	if closeErr := c.CloseRead(); closeErr != nil {
		err = multierror.Append(err, closeErr)
	}
	return err
}

func (c *PipeConn) CloseWrite() error {
	var err error
	c.wc.Do(func() {
		err = c.w.Close()
	})
	return err
}

func (c *PipeConn) CloseRead() error {
	var err error
	c.wc.Do(func() {
		err = c.r.Close()
	})
	return err
}

func (c *PipeConn) LocalAddr() net.Addr {
	return PipeAddr{
		rfd: c.r.Fd(),
		wfd: c.w.Fd(),
	}
}

func (c *PipeConn) RemoteAddr() net.Addr {
	return c.LocalAddr()
}

func (c *PipeConn) SetReadDeadline(t time.Time) error {
	return c.r.SetReadDeadline(t)
}

func (c *PipeConn) SetWriteDeadline(t time.Time) error {
	return c.w.SetWriteDeadline(t)
}

func (c *PipeConn) SetDeadline(t time.Time) error {
	var err error
	if cErr := c.SetReadDeadline(t); err != nil {
		err = multierror.Append(err, cErr)
	}
	if cErr := c.SetWriteDeadline(t); err != nil {
		err = multierror.Append(err, cErr)
	}
	return err
}

var _ net.Conn = new(PipeConn)
