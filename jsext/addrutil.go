package jsext

import (
	"context"
	"encoding/binary"
	"math/big"
	"net"
	"net/netip"
	"time"

	"github.com/dop251/goja"
)

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

var DefaultResolver Resolver = net.DefaultResolver

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
			return vm.ToValue(binary.BigEndian.Uint32(addr.AsSlice()))
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
