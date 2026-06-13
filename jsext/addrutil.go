package jsext

import (
	"context"
	"encoding/binary"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/dop251/goja"
)

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

var DefaultResolver Resolver = net.DefaultResolver

func ipv4ToUint32(ip netip.Addr) uint32 {
	return binary.BigEndian.Uint32(ip.AsSlice())
}

func AddConvertAddr(vm *goja.Runtime) error {
	return vm.GlobalObject().Set("convert_addr", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 1 {
			return goja.NaN()
		}
		addr, err := netip.ParseAddr(call.Argument(0).String())
		if err != nil {
			return goja.NaN()
		}
		if addr.Is4() {
			return vm.ToValue(ipv4ToUint32(addr))
		} else {
			bi := new(big.Int)
			bi.SetBytes(addr.AsSlice())
			return vm.ToValue(bi)
		}
	})
}

var probingAddresses = []string{
	"8.8.8.8",
	"2001:4860:4860::8888",
	"10.0.0.0",
	"172.16.0.0",
	"192.168.0.0",
	"FC00::",
}

var fallbackOwnAddress = netip.MustParseAddr("127.0.0.1")

func probeRoute(dst string) (src netip.Addr) {
	c, err := net.Dial("udp", net.JoinHostPort(dst, "53"))
	if err != nil {
		return
	}
	defer c.Close()
	a := c.LocalAddr()
	if a == nil {
		return
	}

	if na, ok := a.(interface{ AddrPort() netip.AddrPort }); ok {
		return na.AddrPort().Addr()
	}
	return
}

func myIPAddress() netip.Addr {
	for _, a := range probingAddresses {
		myIP := probeRoute(a)
		if myIP.IsValid() {
			return myIP
		}
	}
	return fallbackOwnAddress
}

func AddMyIPAddress(vm *goja.Runtime) error {
	return vm.GlobalObject().Set("myIpAddress", func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(myIPAddress().String())
	})
}

func dnsResolve(host string) (res netip.Addr) {
	ctx, cl := context.WithTimeout(context.Background(), 5*time.Second)
	defer cl()
	// lookup "ip" network for better cache coherence with other lookups,
	// even though we actually interested only in IPv4 only
	addrs, err := DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return
	}
	for _, ip := range addrs {
		ip = ip.Unmap()
		if ip.Is4() {
			return ip
		}
	}
	return
}

func AddDNSResolve(vm *goja.Runtime) error {
	return vm.GlobalObject().Set("dnsResolve", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) != 1 {
			panic(vm.NewTypeError("dnsResolve expects exactly 1 argument"))
		}
		res := dnsResolve(call.Argument(0).String())
		if res.IsValid() {
			return vm.ToValue(res.String())
		}
		return goja.Null()
	})
}

func AddIsResolvable(vm *goja.Runtime) error {
	return vm.GlobalObject().Set("isResolvable", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) != 1 {
			panic(vm.NewTypeError("isResolvable expects exactly 1 argument"))
		}
		res := dnsResolve(call.Argument(0).String())
		return vm.ToValue(res.IsValid())
	})
}

func AddIsInNet(vm *goja.Runtime) error {
	return vm.GlobalObject().Set("isInNet", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) != 3 {
			panic(vm.NewTypeError("isInNet expects exactly 3 arguments"))
		}
		res := dnsResolve(call.Argument(0).String())
		if !res.IsValid() {
			return vm.ToValue(false)
		}
		pattern, err := netip.ParseAddr(call.Argument(1).String())
		if err != nil || !pattern.Is4() {
			return vm.ToValue(false)
		}
		mask, err := netip.ParseAddr(call.Argument(2).String())
		if err != nil || !pattern.Is4() {
			return vm.ToValue(false)
		}
		m := ipv4ToUint32(mask)
		p := ipv4ToUint32(pattern)
		r := ipv4ToUint32(res)
		return vm.ToValue(r&m == p&m)
	})
}

func myIPAddressEx() []netip.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	res := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		na, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}
		res = append(res, na.Unmap())
	}
	return res
}

func AddMyIPAddressEx(vm *goja.Runtime) error {
	return vm.GlobalObject().Set("myIpAddressEx", func(call goja.FunctionCall) goja.Value {
		res := mapSlice(myIPAddressEx(), func(a netip.Addr) string { return a.String() })
		return vm.ToValue(strings.Join(res, ";"))
	})
}

func netipAddrCmp(a, b netip.Addr) int {
	if a.Is6() == b.Is6() {
		if a.Less(b) {
			return -1
		} else if b.Less(a) {
			return 1
		}
		return 0
	} else {
		if a.Is6() {
			return -1
		} else {
			return 1
		}
	}
}

func AddSortIPAddressList(vm *goja.Runtime) error {
	return vm.GlobalObject().Set("sortIpAddressList", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) != 1 {
			panic(vm.NewTypeError("sortIpAddressList expects exactly 1 argument"))
		}
		addrParts := strings.Split(call.Argument(0).String(), ";")
		addrs := make([]netip.Addr, 0, len(addrParts))
		for _, part := range addrParts {
			addr, err := netip.ParseAddr(part)
			if err != nil {
				return vm.ToValue("")
			}
			addrs = append(addrs, addr)
		}
		slices.SortFunc(addrs, netipAddrCmp)
		res := mapSlice(addrs, func(a netip.Addr) string { return a.String() })
		return vm.ToValue(strings.Join(res, ";"))
	})
}

func dnsResolveEx(host string) []netip.Addr {
	ctx, cl := context.WithTimeout(context.Background(), 5*time.Second)
	defer cl()
	// lookup "ip" network for better cache coherence with other lookups,
	// even though we actually interested only in IPv4 only
	addrs, err := DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil
	}
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}
	return addrs
}

func AddDNSResolveEx(vm *goja.Runtime) error {
	return vm.GlobalObject().Set("dnsResolveEx", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) != 1 {
			panic(vm.NewTypeError("dnsResolveEx expects exactly 1 argument"))
		}
		res := mapSlice(dnsResolveEx(call.Argument(0).String()), func(a netip.Addr) string { return a.String() })
		return vm.ToValue(strings.Join(res, ";"))
	})
}

func AddIsResolvableEx(vm *goja.Runtime) error {
	return vm.GlobalObject().Set("isResolvableEx", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) != 1 {
			panic(vm.NewTypeError("isResolvableEx expects exactly 1 argument"))
		}
		res := dnsResolveEx(call.Argument(0).String())
		return vm.ToValue(len(res) > 0)
	})
}
