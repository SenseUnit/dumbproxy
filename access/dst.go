package access

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
)

type DstAddrFilter struct {
	pfxList []netip.Prefix
	next    Filter
}

var ErrDestinationAddressNotAllowed = errors.New("destination address not allowed")

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
			return ErrDestinationAddressNotAllowed
		}
	}
	if f.next != nil {
		return f.next.Access(ctx, req, username, network, address)
	}
	return nil
}
