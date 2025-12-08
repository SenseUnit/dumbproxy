package forward

import (
	"context"
	"io"
)

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

func PairConnections(ctx context.Context, username string, incoming, outgoing io.ReadWriteCloser, _, _ string) error {
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
