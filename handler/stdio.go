package handler

import (
	"context"
	"fmt"
	"net"
	"sync"

	clog "github.com/SenseUnit/dumbproxy/log"

	"github.com/SenseUnit/dumbproxy/dialer"
)

func StdIOHandler(d HandlerDialer, logger *clog.CondLogger, forward ForwardFunc) func(context.Context, dialer.ReadPipe, dialer.WritePipe, string) error {
	return func(ctx context.Context, reader dialer.ReadPipe, writer dialer.WritePipe, dstAddress string) error {
		logger.Debug("Request: %v => %v %q %v %v %v", "<stdio>", "<stdio>", "", "STDIO", "CONNECT", dstAddress)
		target, err := d.DialContext(ctx, "tcp", dstAddress)
		if err != nil {
			return fmt.Errorf("connect to %q failed: %w", dstAddress, err)
		}
		defer target.Close()

		return forward(ctx, "", dialer.NewPipeConn(reader, writer), target)
	}
}

type DummyAddress struct {
	network string
	address string
}

func (a DummyAddress) Network() string {
	return a.network
}

func (a DummyAddress) String() string {
	return a.address
}

type DummyListener struct {
	address   DummyAddress
	closed    chan struct{}
	closeOnce sync.Once
}

// Accept waits for and returns the next connection to the listener.
func (l *DummyListener) Accept() (net.Conn, error) {
	<-l.closed
	return nil, net.ErrClosed
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (l *DummyListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closed)
	})
	return nil
}

// Addr returns the listener's network address.
func (l *DummyListener) Addr() net.Addr {
	return l.address
}

func DummyListen(network, address string) (net.Listener, error) {
	return &DummyListener{
		address: DummyAddress{
			network: network,
			address: address,
		},
		closed: make(chan struct{}),
	}, nil
}
