package certcache

import (
	"context"
	"io"
	"time"

	"github.com/Snawoot/secache"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/sync/singleflight"
)

type certCacheKey = string
type certCacheValue struct {
	ts  time.Time
	res []byte
	err error
}

type LocalCertCache struct {
	cache secache.Cache[certCacheKey, *certCacheValue]
	sf    singleflight.Group
	next  autocert.Cache
}

func NewLocalCertCache(next autocert.Cache, ttl time.Duration) *LocalCertCache {
	return &LocalCertCache{
		cache: *(secache.New[certCacheKey, *certCacheValue](3, func(key certCacheKey, item *certCacheValue) bool {
			return time.Now().Before(item.ts.Add(ttl))
		})),
		next: next,
	}
}

func (cc *LocalCertCache) Get(ctx context.Context, key string) ([]byte, error) {
	resItem, ok := cc.cache.GetValidOrDelete(key)
	if !ok {
		v, _, _ := cc.sf.Do(key, func() (any, error) {
			res, err := cc.next.Get(ctx, key)
			item := &certCacheValue{
				ts:  time.Now(),
				res: res,
				err: err,
			}
			if ctx.Err() == nil {
				cc.cache.Set(key, item)
			}
			return item, err
		})
		resItem = v.(*certCacheValue)
	}
	return resItem.res, resItem.err
}

func (cc *LocalCertCache) Put(ctx context.Context, key string, data []byte) error {
	cc.cache.Set(key, &certCacheValue{
		ts:  time.Now(),
		res: data,
		err: nil,
	})
	return cc.next.Put(ctx, key, data)
}

func (cc *LocalCertCache) Delete(ctx context.Context, key string) error {
	cc.cache.Delete(key)
	return cc.next.Delete(ctx, key)
}

func (cc *LocalCertCache) Close() error {
	if cacheCloser, ok := cc.next.(io.Closer); ok {
		return cacheCloser.Close()
	}
	return nil
}

var _ autocert.Cache = new(LocalCertCache)
