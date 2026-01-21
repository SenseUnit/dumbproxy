package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/Snawoot/secache"
	"github.com/hashicorp/go-multierror"
	"golang.org/x/sync/singleflight"

	"github.com/SenseUnit/dumbproxy/dialer/dto"
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

type NameResolveCachingDialer struct {
	resolver Resolver
	cache    secache.Cache[resolverCacheKey, *resolverCacheValue]
	sf       singleflight.Group
	posTTL   time.Duration
	negTTL   time.Duration
	timeout  time.Duration
	next     Dialer
}

func NewNameResolveCachingDialer(next Dialer, resolver Resolver, posTTL, negTTL, timeout time.Duration) *NameResolveCachingDialer {
	//	func(c *ttlcache.Cache[resolverCacheKey, resolverCacheValue], key resolverCacheKey) *ttlcache.Item[resolverCacheKey, resolverCacheValue] {
	//	},
	return &NameResolveCachingDialer{
		resolver: resolver,
		cache: *(secache.New[resolverCacheKey, *resolverCacheValue](
			3,
			func(key resolverCacheKey, item *resolverCacheValue) bool {
				return time.Now().Before(item.expires)
			},
		)),
		posTTL:  posTTL,
		negTTL:  negTTL,
		timeout: timeout,
		next:    next,
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
	key := resolverCacheKey{
		network: resolveNetwork,
		host:    host,
	}

	res, ok := nrcd.cache.GetValidOrDelete(key)
	if !ok {
		v, _, _ := nrcd.sf.Do(key.network+":"+key.host, func() (any, error) {
			ctx, cl := context.WithTimeout(context.Background(), nrcd.timeout)
			defer cl()
			res, err := nrcd.resolver.LookupNetIP(ctx, key.network, key.host)
			for i := range res {
				res[i] = res[i].Unmap()
			}
			setTTL := nrcd.negTTL
			if err == nil {
				setTTL = nrcd.posTTL
			}
			item := &resolverCacheValue{
				expires: time.Now().Add(setTTL),
				addrs:   res,
				err:     err,
			}
			nrcd.cache.Set(key, item)
			return item, nil
		})
		res = v.(*resolverCacheValue)
	}

	if res.err != nil {
		return nil, res.err
	}

	ctx = dto.OrigDstToContext(ctx, address)

	var dialErr error
	var conn net.Conn

	for _, ip := range res.addrs {
		conn, err = nrcd.next.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		dialErr = multierror.Append(dialErr, err)
		var sae dto.StopAddressIteration
		if errors.As(err, &sae) {
			break
		}
	}

	return nil, fmt.Errorf("failed to dial %s: %w", address, dialErr)
}

func (nrcd *NameResolveCachingDialer) Dial(network, address string) (net.Conn, error) {
	return nrcd.DialContext(context.Background(), network, address)
}

func (nrcd *NameResolveCachingDialer) WantsHostname(ctx context.Context, net, address string) bool {
	return WantsHostname(ctx, net, address, nrcd.next)
}

var _ Dialer = new(NameResolveCachingDialer)
var _ HostnameWanter = new(NameResolveCachingDialer)
