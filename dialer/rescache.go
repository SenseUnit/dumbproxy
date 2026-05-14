package dialer

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"codeberg.org/yarmak/secache"
	"golang.org/x/sync/singleflight"
)

type resolverCacheKey struct {
	network string
	host    string
}

type resolverCacheValue struct {
	expires time.Time
	addrs   []netip.Addr
	err     error
}

type CachingResolver struct {
	next    Resolver
	cache   secache.Cache[resolverCacheKey, *resolverCacheValue]
	sf      singleflight.Group
	posTTL  time.Duration
	negTTL  time.Duration
	timeout time.Duration
}

func NewCachingResolver(next Resolver, posTTL, negTTL, timeout time.Duration) *CachingResolver {
	return &CachingResolver{
		next: next,
		cache: *(secache.New[resolverCacheKey, *resolverCacheValue](
			3,
			func(key resolverCacheKey, item *resolverCacheValue) bool {
				return time.Now().Before(item.expires)
			},
		)),
		posTTL:  posTTL,
		negTTL:  negTTL,
		timeout: timeout,
	}
}

func (r *CachingResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		// literal IP address, just do unmapping
		return r.next.LookupNetIP(ctx, network, addr.Unmap().String())
	}

	host = strings.ToLower(host)
	key := resolverCacheKey{
		network: network,
		host:    host,
	}

	res, ok := r.cache.GetValidOrDelete(key)
	if !ok {
		v, _, _ := r.sf.Do(key.network+":"+key.host, func() (any, error) {
			ctx, cl := context.WithTimeout(context.Background(), r.timeout)
			defer cl()
			res, err := r.next.LookupNetIP(ctx, key.network, key.host)
			for i := range res {
				res[i] = res[i].Unmap()
			}
			setTTL := r.negTTL
			if err == nil {
				setTTL = r.posTTL
			}
			item := &resolverCacheValue{
				expires: time.Now().Add(setTTL),
				addrs:   res,
				err:     err,
			}
			r.cache.Set(key, item)
			return item, nil
		})
		res = v.(*resolverCacheValue)
	}

	if res.err != nil {
		return nil, res.err
	}

	return res.addrs, nil
}

var _ Resolver = new(CachingResolver)
