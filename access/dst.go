package access

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
)

type DstAddrFilter struct {
	pfxList []netip.Prefix
	next    Filter
}

type ErrDestinationAddressNotAllowed struct {
	a netip.Addr
	p netip.Prefix
}

func (e ErrDestinationAddressNotAllowed) Error() string {
	return fmt.Sprintf("destination address %s is not allowed by filter prefix %s",
		e.a.String(), e.p.String())
}

func NewDstAddrFilter(prefixes []netip.Prefix, next Filter) DstAddrFilter {
	return DstAddrFilter{
		pfxList: prefixes,
		next:    next,
	}
}

func (f DstAddrFilter) Access(ctx context.Context, req *http.Request, username, network, address string) error {
	addrport, err := netip.ParseAddrPort(address)
	if err != nil {
		// not an IP address, no action needed
		return f.next.Access(ctx, req, username, network, address)
	}
	addr := addrport.Addr().Unmap()
	for _, pfx := range f.pfxList {
		if pfx.Contains(addr) {
			return ErrDestinationAddressNotAllowed{addr, pfx}
		}
	}
	return f.next.Access(ctx, req, username, network, address)
}
