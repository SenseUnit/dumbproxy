package jsext

import (
	"encoding/binary"
	"math/big"
	"net"
	"net/netip"

	"github.com/dop251/goja"
)

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
