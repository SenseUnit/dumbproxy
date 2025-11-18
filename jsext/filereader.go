package jsext

import (
	"os"

	"github.com/dop251/goja"
)

func AddFileReader(vm *goja.Runtime) error {
	return vm.Set("readFile", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) != 1 {
			panic(vm.NewTypeError("readFile expects exactly 1 argument"))
		}

		filename := call.Argument(0).String()
		content, err := os.ReadFile(filename)
		if err != nil {
			panic(vm.NewGoError(err))
		}

		return vm.ToValue(string(content))
	})
}
