package dialer

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/jellydator/ttlcache/v3"
)

type resolverCacheKey struct {
	network string
	host    string
}

type resolverCacheValue struct {
	addrs []netip.Addr
	err   error
}

type NameResolveCachingDialer struct {
	cache     *ttlcache.Cache[resolverCacheKey, resolverCacheValue]
	next      Dialer
	startOnce sync.Once
	stopOnce  sync.Once
}

func NewNameResolveCachingDialer(next Dialer, resolver Resolver, posTTL, negTTL, timeout time.Duration) *NameResolveCachingDialer {
	cache := ttlcache.New[resolverCacheKey, resolverCacheValue](
		ttlcache.WithDisableTouchOnHit[resolverCacheKey, resolverCacheValue](),
		ttlcache.WithLoader(
			ttlcache.NewSuppressedLoader(
				ttlcache.LoaderFunc[resolverCacheKey, resolverCacheValue](
					func(c *ttlcache.Cache[resolverCacheKey, resolverCacheValue], key resolverCacheKey) *ttlcache.Item[resolverCacheKey, resolverCacheValue] {
						ctx, cl := context.WithTimeout(context.Background(), timeout)
						defer cl()
						res, err := resolver.LookupNetIP(ctx, key.network, key.host)
						for i := range res {
							res[i] = res[i].Unmap()
						}
						setTTL := negTTL
						if err == nil {
							setTTL = posTTL
						}
						return c.Set(key, resolverCacheValue{
							addrs: res,
							err:   err,
						}, setTTL)
					},
				),
				nil),
		),
	)
	return &NameResolveCachingDialer{
		cache: cache,
		next:  next,
	}
}

func (nrcd *NameResolveCachingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if WantsHostname(ctx, network, address, nrcd.next) {
		return nrcd.next.DialContext(ctx, network, address)
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("failed to extract host and port from %s: %w", address, err)
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		// literal IP address, just do unmapping
		return nrcd.next.DialContext(ctx, network, net.JoinHostPort(addr.Unmap().String(), port))
	}

	var resolveNetwork string
	switch network {
	case "udp4", "tcp4", "ip4":
		resolveNetwork = "ip4"
	case "udp6", "tcp6", "ip6":
		resolveNetwork = "ip6"
	case "udp", "tcp", "ip":
		resolveNetwork = "ip"
	default:
		return nil, fmt.Errorf("resolving dial %q: unsupported network %q", address, network)
	}

	host = strings.ToLower(host)

	resItem := nrcd.cache.Get(resolverCacheKey{
		network: resolveNetwork,
		host:    host,
	})
	if resItem == nil {
		return nil, fmt.Errorf("cache lookup failed for pair <%q, %q>", resolveNetwork, host)
	}

	res := resItem.Value()
	if res.err != nil {
		return nil, res.err
	}

	ctx = OrigDstToContext(ctx, address)

	var dialErr error
	var conn net.Conn

	for _, ip := range res.addrs {
		conn, err = nrcd.next.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		dialErr = multierror.Append(dialErr, err)
	}

	return nil, fmt.Errorf("failed to dial %s: %w", address, dialErr)
}

func (nrcd *NameResolveCachingDialer) Dial(network, address string) (net.Conn, error) {
	return nrcd.DialContext(context.Background(), network, address)
}

func (nrcd *NameResolveCachingDialer) WantsHostname(ctx context.Context, net, address string) bool {
	return WantsHostname(ctx, net, address, nrcd.next)
}

func (nrcd *NameResolveCachingDialer) Start() {
	nrcd.startOnce.Do(func() {
		go nrcd.cache.Start()
	})
}

func (nrcd *NameResolveCachingDialer) Stop() {
	nrcd.stopOnce.Do(nrcd.cache.Stop)
}

var _ Dialer = new(NameResolveCachingDialer)
var _ HostnameWanter = new(NameResolveCachingDialer)
