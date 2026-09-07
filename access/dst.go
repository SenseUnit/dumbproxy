package access

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
)

type AddressChecker interface {
	Contains(ip netip.Addr) bool
}

type DstAddrFilter struct {
	checker AddressChecker
	next    Filter
}

type ErrDestinationAddressNotAllowed struct {
	a netip.Addr
}

func (e ErrDestinationAddressNotAllowed) Error() string {
	return fmt.Sprintf("destination address %s is not allowed by destination address filter", e.a.String())
}

func NewDstAddrFilter(checker AddressChecker, next Filter) DstAddrFilter {
	return DstAddrFilter{
		checker: checker,
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
	if f.checker.Contains(addr) {
		return ErrDestinationAddressNotAllowed{addr}
	}
	return f.next.Access(ctx, req, username, network, address)
}
