package jsext

import (
	"encoding/binary"
	"math/big"
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
