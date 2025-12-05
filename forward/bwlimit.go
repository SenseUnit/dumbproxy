package forward

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/Snawoot/secache"
	"github.com/Snawoot/secache/randmap"

	"github.com/SenseUnit/dumbproxy/rate"
)

const copyChunkSize = 128 * 1024

type cacheItem struct {
	mux sync.RWMutex
	ul  rate.Limiter
	dl  rate.Limiter
}

func (i *cacheItem) rLock() {
	i.mux.RLock()
}

func (i *cacheItem) rUnlock() {
	i.mux.RUnlock()
}

func (i *cacheItem) tryLock() bool {
	return i.mux.TryLock()
}

func (i *cacheItem) unlock() {
	i.mux.Unlock()
}

type BWLimit struct {
	bps      float64
	burst    int64
	separate bool
	cache    secache.Cache[string, *cacheItem]
}

func NewBWLimit(bytesPerSecond float64, burst int64, separate bool) *BWLimit {
	return &BWLimit{
		bps:      bytesPerSecond,
		burst:    burst,
		separate: separate,
		cache: *(secache.New[string, *cacheItem](3, func(_ string, item *cacheItem) bool {
			if item.tryLock() {
				if item.ul.Tokens() >= float64(item.ul.Burst()) && item.dl.Tokens() >= float64(item.dl.Burst()) {
					return false
				}
				item.unlock()
			}
			return true
		})),
	}
}

func (l *BWLimit) copy(ctx context.Context, rl *rate.Limiter, dst io.Writer, src io.Reader) (written int64, err error) {
	lim := &io.LimitedReader{
		R: src,
		N: copyChunkSize,
	}
	var n int64
	for {
		t := time.Now()
		r := rl.ReserveN(t, copyChunkSize)
		if !r.OK() {
			err = errors.New("can't get rate limit reservation")
			return
		}
		delay := r.DelayFrom(t)
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				err = ctx.Err()
				return
			}
		}
		n, err = io.Copy(dst, lim)
		written += n
		if n < copyChunkSize {
			r.CancelAt(t)
			if n > 0 {
				rl.ReserveN(t, n)
			}
		}
		if err != nil {
			return
		}
		if lim.N > 0 {
			// EOF from underlying stream
			return
		}
		lim.N = copyChunkSize
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

func (l *BWLimit) getRatelimiters(username string) (res *cacheItem) {
	l.cache.Do(func(m *randmap.RandMap[string, *cacheItem]) {
		var ok bool
		res, ok = m.Get(username)
		if ok {
			res.rLock()
		} else {
			ul := rate.NewLimiter(rate.Limit(l.bps), max(copyChunkSize, l.burst))
			dl := ul
			if l.separate {
				dl = rate.NewLimiter(rate.Limit(l.bps), max(copyChunkSize, l.burst))
			}
			res = &cacheItem{
				ul: *ul,
				dl: *dl,
			}
			res.rLock()
			l.cache.SetLocked(m, username, res)
		}
		return
	})
	return
}

func (l *BWLimit) PairConnections(ctx context.Context, username string, incoming, outgoing io.ReadWriteCloser) error {
	ci := l.getRatelimiters(username)
	defer ci.rUnlock()

	var err error
	i2oErr := make(chan error, 1)
	o2iErr := make(chan error, 1)
	ctxErr := ctx.Done()

	go l.futureCopyAndCloseWrite(ctx, i2oErr, &ci.ul, outgoing, incoming)
	go l.futureCopyAndCloseWrite(ctx, o2iErr, &ci.dl, incoming, outgoing)

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
