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
	return fmt.Sprintf("destionation address %s not allowed by filter prefix %s",
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
		return nil
	}
	for _, pfx := range f.pfxList {
		if pfx.Contains(addrport.Addr()) {
			return ErrDestinationAddressNotAllowed{addrport.Addr(), pfx}
		}
	}
	if f.next != nil {
		return f.next.Access(ctx, req, username, network, address)
	}
	return nil
}
