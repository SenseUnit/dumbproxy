package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/Snawoot/secache"
	"github.com/Snawoot/secache/randmap"

	clog "github.com/SenseUnit/dumbproxy/log"
	"github.com/SenseUnit/dumbproxy/rate"
)

const copyChunkSize = 128 * 1024

type LimitKind int

const (
	LimitKindNone LimitKind = iota
	LimitKindStatic
	LimitKindJS
)

type LimitSpec struct {
	Kind LimitKind
	Spec any
}

type StaticLimitSpec struct {
	BPS      uint64
	Burst    int64
	Separate bool
}

type JSLimitSpec struct {
	Filename  string
	Instances int
}

type LimitParameters struct {
	UploadBPS     float64 `json:"uploadBPS"`
	UploadBurst   int64   `json:"uploadBurst"`
	DownloadBPS   float64 `json:"downloadBPS"`
	DownloadBurst int64   `json:"downloadBurst"`
	GroupKey      *string `json:"groupKey"`
	Separate      bool    `json:"separate"`
}

type LimitProvider = func(context.Context, string, string, string) (*LimitParameters, error)

func ProviderFromSpec(spec LimitSpec, logger *clog.CondLogger) (LimitProvider, error) {
	switch spec.Kind {
	case LimitKindStatic:
		staticSpec, ok := spec.Spec.(StaticLimitSpec)
		if !ok {
			return nil, fmt.Errorf("incorrect payload type in BW limit spec: %T", spec)
		}
		return func(_ context.Context, username, _, _ string) (*LimitParameters, error) {
			return &LimitParameters{
				UploadBPS:     float64(staticSpec.BPS),
				UploadBurst:   staticSpec.Burst,
				DownloadBPS:   float64(staticSpec.BPS),
				DownloadBurst: staticSpec.Burst,
				GroupKey:      &username,
				Separate:      staticSpec.Separate,
			}, nil
		}, nil
	case LimitKindJS:
		jsSpec, ok := spec.Spec.(JSLimitSpec)
		if !ok {
			return nil, fmt.Errorf("incorrect payload type in BW limit spec: %T", spec)
		}
		j, err := NewJSLimitProvider(jsSpec.Filename, jsSpec.Instances, logger)
		if err != nil {
			return nil, err
		}
		return j.Parameters, nil
	}
	return nil, fmt.Errorf("unsupported BW limit kind %d", int(spec.Kind))
}

type cacheItem struct {
	mux sync.RWMutex
	ul  *rate.Limiter
	dl  *rate.Limiter
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
	paramFn LimitProvider
	cache   secache.Cache[string, *cacheItem]
}

func NewBWLimit(p LimitProvider) *BWLimit {
	return &BWLimit{
		paramFn: p,
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

func (l *BWLimit) getRatelimiters(ctx context.Context, username, network, address string) (*cacheItem, error) {
	params, err := l.paramFn(ctx, username, network, address)
	if err != nil {
		return nil, err
	}
	groupKey := username
	if params.GroupKey != nil {
		groupKey = *params.GroupKey
	}
	var res *cacheItem
	l.cache.Do(func(m *randmap.RandMap[string, *cacheItem]) {
		var ok bool
		res, ok = m.Get(groupKey)
		if ok {
			res.rLock()
		} else {
			ul := rate.NewLimiter(rate.Limit(params.UploadBPS), max(copyChunkSize, params.UploadBurst))
			dl := ul
			if params.Separate {
				dl = rate.NewLimiter(rate.Limit(params.DownloadBPS), max(copyChunkSize, params.DownloadBurst))
			}
			res = &cacheItem{
				ul: ul,
				dl: dl,
			}
			res.rLock()
			l.cache.SetLocked(m, groupKey, res)
		}
		return
	})
	return res, nil
}

func (l *BWLimit) PairConnections(ctx context.Context, username string, incoming, outgoing io.ReadWriteCloser, network, address string) error {
	ci, err := l.getRatelimiters(ctx, username, network, address)
	if err != nil {
		return fmt.Errorf("ratelimit parameter computarion failed for user %q: %w", username, err)
	}
	defer ci.rUnlock()

	i2oErr := make(chan error, 1)
	o2iErr := make(chan error, 1)
	ctxErr := ctx.Done()

	go l.futureCopyAndCloseWrite(ctx, i2oErr, ci.ul, outgoing, incoming)
	go l.futureCopyAndCloseWrite(ctx, o2iErr, ci.dl, incoming, outgoing)

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
