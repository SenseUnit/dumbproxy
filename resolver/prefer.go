package resolver

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

type Preference int

const (
	PreferenceNothing Preference = iota
	PreferenceIPv4
	PreferenceIPv6
)

func (p Preference) String() string {
	switch p {
	case PreferenceNothing:
		return "none"
	case PreferenceIPv4:
		return "ipv4"
	case PreferenceIPv6:
		return "ipv6"
	default:
		return fmt.Sprintf("Preference(%d)", int(p))
	}
}

func ParsePreference(p string) (Preference, error) {
	var res Preference
	switch lp := strings.ToLower(p); lp {
	case "none", "nothing", "any", "anything":
		res = PreferenceNothing
	case "ipv4", "ip4", "v4", "4":
		res = PreferenceIPv4
	case "ipv6", "ip6", "v6", "6":
		res = PreferenceIPv6
	default:
		return 0, fmt.Errorf("unknown preference specification %q", p)
	}
	return res, nil
}

func boolToInt(x bool) int {
	if x {
		return 0
	}
	return 1
}

type PreferIPv4 struct {
	LookupNetIPer
}

func (p PreferIPv4) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	addrs, err := p.LookupNetIPer.LookupNetIP(ctx, network, host)
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(addrs, func(a, b netip.Addr) int {
		return cmp.Compare(
			boolToInt(a.Unmap().Is4()),
			boolToInt(b.Unmap().Is4()),
		)
	})
	return addrs, nil
}

type PreferIPv6 struct {
	LookupNetIPer
}

func (p PreferIPv6) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	addrs, err := p.LookupNetIPer.LookupNetIP(ctx, network, host)
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(addrs, func(a, b netip.Addr) int {
		return cmp.Compare(
			boolToInt(a.Unmap().Is6()),
			boolToInt(b.Unmap().Is6()),
		)
	})
	return addrs, nil
}

func Prefer(resolver LookupNetIPer, p Preference) LookupNetIPer {
	switch p {
	case PreferenceNothing:
		return resolver
	case PreferenceIPv4:
		return PreferIPv4{resolver}
	case PreferenceIPv6:
		return PreferIPv6{resolver}
	}
	panic("unknown address family preference")
}
