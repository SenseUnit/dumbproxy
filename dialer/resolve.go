package dialer

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/hashicorp/go-multierror"
)

type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type NameResolvingDialer struct {
	next     Dialer
	resolver Resolver
}

func NewNameResolvingDialer(next Dialer, resolver Resolver) NameResolvingDialer {
	return NameResolvingDialer{
		next:     next,
		resolver: resolver,
	}
}

type origDstKey struct{}

func OrigDstFromContext(ctx context.Context) (string, bool) {
	orig, ok := ctx.Value(origDstKey{}).(string)
	return orig, ok
}

func OrigDstToContext(ctx context.Context, dst string) context.Context {
	return context.WithValue(ctx, origDstKey{}, dst)
}

func (nrd NameResolvingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if WantsHostname(ctx, network, address, nrd.next) {
		return nrd.next.DialContext(ctx, network, address)
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("failed to extract host and port from %s: %w", address, err)
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		// literal IP address, just do unmapping
		return nrd.next.DialContext(ctx, network, net.JoinHostPort(addr.Unmap().String(), port))
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

	res, err := nrd.resolver.LookupNetIP(ctx, resolveNetwork, host)
	if err != nil {
		return nil, fmt.Errorf("resolving %q (%s) failed: %w", host, network, err)
	}
	for i := range res {
		res[i] = res[i].Unmap()
	}

	ctx = OrigDstToContext(ctx, address)

	var dialErr error
	var conn net.Conn

	for _, ip := range res {
		conn, err = nrd.next.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		dialErr = multierror.Append(dialErr, err)
	}

	return nil, fmt.Errorf("failed to dial %s: %w", address, dialErr)
}

func (nrd NameResolvingDialer) Dial(network, address string) (net.Conn, error) {
	return nrd.DialContext(context.Background(), network, address)
}

func (nrd NameResolvingDialer) WantsHostname(ctx context.Context, net, address string) bool {
	return WantsHostname(ctx, net, address, nrd.next)
}

var _ Dialer = NameResolvingDialer{}
var _ HostnameWanter = NameResolvingDialer{}
