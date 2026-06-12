package jsext

import (
	"strings"

	"github.com/dop251/goja"
)

func AddIsPlainHostName(vm *goja.Runtime) error {
	return vm.GlobalObject().Set("isPlainHostName", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 1 {
			return vm.ToValue(true)
		}
		return vm.ToValue(!strings.Contains(call.Argument(0).String(), "."))
	})
}
