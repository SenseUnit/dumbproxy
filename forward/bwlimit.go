package forward

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/ajwerner/orderstat"

	"github.com/SenseUnit/dumbproxy/rate"
)

const copyChunkSize = 128 * 1024

type treeItem struct {
	key string
	mux sync.RWMutex
	ul  *rate.Limiter
	dl  *rate.Limiter
}

func (i *treeItem) Less(other orderstat.Item) bool {
	return other.(*treeItem).key > i.key
}

func (i *treeItem) rLock() {
	i.mux.RLock()
}

func (i *treeItem) rUnlock() {
	i.mux.RUnlock()
}

func (i *treeItem) tryLock() bool {
	return i.mux.TryLock()
}

type BWLimit struct {
	mux      sync.Mutex
	m        *orderstat.Tree
	bps      float64
	burst    int64
	separate bool
}

func NewBWLimit(bytesPerSecond float64, burst int64, separate bool) *BWLimit {
	return &BWLimit{
		m:        orderstat.NewTree(),
		bps:      bytesPerSecond,
		burst:    burst,
		separate: separate,
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

func (l *BWLimit) newTreeItem(username string) *treeItem {
	ul := rate.NewLimiter(rate.Limit(l.bps), max(copyChunkSize, l.burst))
	dl := ul
	if l.separate {
		dl = rate.NewLimiter(rate.Limit(l.bps), max(copyChunkSize, l.burst))
	}
	return &treeItem{
		key: username,
		ul:  ul,
		dl:  dl,
	}
}

const randomEvictions = 2

func (l *BWLimit) evictRandom() {
	for _ = range randomEvictions {
		n := l.m.Len()
		if n == 0 {
			return
		}
		item := l.m.Select(rand.IntN(n))
		if item == nil {
			panic("random tree sampling failed")
		}
		ti := item.(*treeItem)
		if ti.tryLock() {
			if ti.ul.Tokens() >= float64(ti.ul.Burst()) && ti.dl.Tokens() >= float64(ti.dl.Burst()) {
				// RL is full and nobody touches it. Removing...
				l.m.Delete(item)
			}
		}
	}
}

func (l *BWLimit) getRatelimiters(username string) *treeItem {
	l.mux.Lock()
	defer l.mux.Unlock()
	item := l.m.Get(&treeItem{
		key: username,
	})
	if item == nil {
		ti := l.newTreeItem(username)
		ti.rLock()
		l.m.ReplaceOrInsert(ti)
		l.evictRandom()
		return ti
	}
	ti := item.(*treeItem)
	ti.rLock()
	return ti
}

func (l *BWLimit) PairConnections(ctx context.Context, username string, incoming, outgoing io.ReadWriteCloser) error {
	ti := l.getRatelimiters(username)
	defer ti.rUnlock()

	var err error
	i2oErr := make(chan error, 1)
	o2iErr := make(chan error, 1)
	ctxErr := ctx.Done()

	go l.futureCopyAndCloseWrite(ctx, i2oErr, ti.ul, outgoing, incoming)
	go l.futureCopyAndCloseWrite(ctx, o2iErr, ti.dl, incoming, outgoing)

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
