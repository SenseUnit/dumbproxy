package jsext

import (
	"github.com/dop251/goja"

	"github.com/SenseUnit/dumbproxy/dialer/dto"
)

func AddStopAddressIteration(vm *goja.Runtime) error {
	return vm.GlobalObject().Set("newStopAddressIteration", func(call goja.FunctionCall) goja.Value {
		return vm.NewGoError(dto.StopAddressIteration{})
	})
}
