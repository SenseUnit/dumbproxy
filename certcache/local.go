package certcache

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"golang.org/x/crypto/acme/autocert"
)

type certCacheKey = string
type certCacheValue struct {
	res []byte
	err error
}

type LocalCertCache struct {
	cache     *ttlcache.Cache[certCacheKey, certCacheValue]
	next      autocert.Cache
	startOnce sync.Once
	stopOnce  sync.Once
}

func NewLocalCertCache(next autocert.Cache, ttl, timeout time.Duration) *LocalCertCache {
	cache := ttlcache.New[certCacheKey, certCacheValue](
		ttlcache.WithTTL[certCacheKey, certCacheValue](ttl),
		ttlcache.WithLoader(
			ttlcache.NewSuppressedLoader(
				ttlcache.LoaderFunc[certCacheKey, certCacheValue](
					func(c *ttlcache.Cache[certCacheKey, certCacheValue], key certCacheKey) *ttlcache.Item[certCacheKey, certCacheValue] {
						ctx, cl := context.WithTimeout(context.Background(), timeout)
						defer cl()
						res, err := next.Get(ctx, key)
						if err != nil {
							return c.Set(key, certCacheValue{res, err}, -100)
						}
						return c.Set(key, certCacheValue{res, err}, 0)
					},
				),
				nil),
		),
	)
	return &LocalCertCache{
		cache: cache,
		next:  next,
	}
}

func (cc *LocalCertCache) Get(_ context.Context, key string) ([]byte, error) {
	resItem := cc.cache.Get(key).Value()
	return resItem.res, resItem.err
}

func (cc *LocalCertCache) Put(ctx context.Context, key string, data []byte) error {
	cc.cache.Set(key, certCacheValue{data, nil}, 0)
	return cc.next.Put(ctx, key, data)
}

func (cc *LocalCertCache) Delete(ctx context.Context, key string) error {
	cc.cache.Delete(key)
	return cc.next.Delete(ctx, key)
}

func (cc *LocalCertCache) Start() {
	cc.startOnce.Do(func() {
		go cc.cache.Start()
	})
}

func (cc *LocalCertCache) Close() error {
	var err error
	cc.stopOnce.Do(func() {
		cc.cache.Stop()
		if cacheCloser, ok := cc.next.(io.Closer); ok {
			err = cacheCloser.Close()
		}
	})
	return err
}

var _ autocert.Cache = new(LocalCertCache)
