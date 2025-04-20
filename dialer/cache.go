package dialer

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/jellydator/ttlcache/v3"
	xproxy "golang.org/x/net/proxy"
	"golang.org/x/sync/singleflight"
)

type dialerCacheKey struct {
	url  string
	next xproxy.Dialer
}

type dialerCacheValue struct {
	dialer xproxy.Dialer
	err    error
}

var (
	dialerCache = ttlcache.New[dialerCacheKey, dialerCacheValue](
		ttlcache.WithDisableTouchOnHit[dialerCacheKey, dialerCacheValue](),
	)
	dialerCacheSingleFlight = new(singleflight.Group)
)

func GetCachedDialer(u *url.URL, next xproxy.Dialer) (xproxy.Dialer, error) {
	params, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, err
	}
	if !params.Has("url") {
		return nil, errors.New("cached dialer: no \"url\" parameter specified")
	}
	parsedURL, err := url.Parse(params.Get("url"))
	if err != nil {
		return nil, fmt.Errorf("unable to parse proxy URL: %w", err)
	}
	if !params.Has("ttl") {
		return nil, errors.New("cached dialer: no \"ttl\" parameter specified")
	}
	ttl, err := time.ParseDuration(params.Get("ttl"))
	if err != nil {
		return nil, fmt.Errorf("cached dialer: unable to parse TTL duration %q: %w", params.Get("ttl"), err)
	}
	cacheRes := dialerCache.Get(
		dialerCacheKey{
			url:  params.Get("url"),
			next: next,
		},
		ttlcache.WithLoader[dialerCacheKey, dialerCacheValue](
			ttlcache.NewSuppressedLoader[dialerCacheKey, dialerCacheValue](
				ttlcache.LoaderFunc[dialerCacheKey, dialerCacheValue](
					func(c *ttlcache.Cache[dialerCacheKey, dialerCacheValue], key dialerCacheKey) *ttlcache.Item[dialerCacheKey, dialerCacheValue] {
						dialer, err := xproxy.FromURL(parsedURL, next)
						return c.Set(
							key,
							dialerCacheValue{
								dialer: dialer,
								err:    err,
							},
							ttl,
						)
					},
				),
				dialerCacheSingleFlight,
			),
		),
	).Value()
	return cacheRes.dialer, cacheRes.err
}
