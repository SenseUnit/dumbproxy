package forward

import (
	"context"
	"errors"
	"io"

	"github.com/zeebo/xxh3"
	"golang.org/x/time/rate"
)

const copyBufSize = 128 * 1024

type BWLimit struct {
	d []rate.Limiter
	u []rate.Limiter
}

func NewBWLimit(bytesPerSecond float64, buckets uint, separate bool) *BWLimit {
	if buckets == 0 {
		buckets = 1
	}
	lim := *(rate.NewLimiter(rate.Limit(bytesPerSecond), copyBufSize))
	d := make([]rate.Limiter, buckets)
	for i := range d {
		d[i] = lim
	}
	u := d
	if separate {
		u = make([]rate.Limiter, buckets)
		for i := range u {
			u[i] = lim
		}
	}
	return &BWLimit{
		d: d,
		u: u,
	}
}

var errInvalidWrite = errors.New("invalid write result")

func (l *BWLimit) copy(ctx context.Context, rl *rate.Limiter, dst io.Writer, src io.Reader) (written int64, err error) {
	buf := make([]byte, copyBufSize)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			if e := rl.WaitN(ctx, nr); e != nil {
				err = e
				break
			}
			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = errInvalidWrite
				}
			}
			written += int64(nw)
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}

func (l *BWLimit) copyAndCloseWrite(ctx context.Context, rl *rate.Limiter, dst io.WriteCloser, src io.ReadCloser) error {
	_, err := l.copy(ctx, rl, dst, src)
	if closeWriter, ok := dst.(interface {
		CloseWrite() error
	}); ok {
		closeWriter.CloseWrite()
	} else {
		dst.Close()
	}
	return err
}

func (l *BWLimit) futureCopyAndCloseWrite(ctx context.Context, c chan<- error, rl *rate.Limiter, dst io.WriteCloser, src io.ReadCloser) {
	c <- l.copyAndCloseWrite(ctx, rl, dst, src)
	close(c)
}

func (l *BWLimit) getRatelimiters(username string) (*rate.Limiter, *rate.Limiter) {
	idx := int(hashUsername(username, uint64(len(l.d))))
	return &(l.d[idx]), &(l.u[idx])
}

func (l *BWLimit) PairConnections(ctx context.Context, username string, incoming, outgoing io.ReadWriteCloser) error {
	dl, ul := l.getRatelimiters(username)

	var err error
	i2oErr := make(chan error, 1)
	o2iErr := make(chan error, 1)
	ctxErr := ctx.Done()

	go l.futureCopyAndCloseWrite(ctx, i2oErr, ul, outgoing, incoming)
	go l.futureCopyAndCloseWrite(ctx, o2iErr, dl, incoming, outgoing)

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

func hashUsername(s string, nslots uint64) uint64 {
	if nslots == 0 {
		panic("number of slots can't be zero")
	}

	hash := xxh3.New()
	iv := []byte{0}

	if nslots&(nslots-1) == 0 {
		hash.Write(iv)
		hash.Write([]byte(s))
		return hash.Sum64() & (nslots - 1)
	}

	minBiased := -((-nslots) % nslots) // == 2**64 - (2**64%nslots)

	var hv uint64
	for {
		hash.Write(iv)
		hash.Write([]byte(s))
		hv = hash.Sum64()
		if hv < minBiased {
			break
		}
		iv[0]++
		hash.Reset()
	}
	return hv % nslots
}
