package jsext

import (
	"fmt"

	"github.com/dop251/goja"

	clog "github.com/SenseUnit/dumbproxy/log"
)

func AddPrinter(vm *goja.Runtime, logger *clog.CondLogger) error {
	return vm.Set("print", func(call goja.FunctionCall) goja.Value {
		printArgs := make([]interface{}, len(call.Arguments))
		for i, arg := range call.Arguments {
			printArgs[i] = arg
		}
		logger.Info("%s", fmt.Sprintln(printArgs...))
		return goja.Undefined()
	})
}
