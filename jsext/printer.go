package jsext

import (
	"fmt"

	"github.com/dop251/goja"

	clog "github.com/SenseUnit/dumbproxy/log"
)

func AddPrinter(vm *goja.Runtime, logger *clog.CondLogger) error {
	if err := vm.GlobalObject().Set("print", func(call goja.FunctionCall) goja.Value {
		printArgs := make([]any, len(call.Arguments))
		for i, arg := range call.Arguments {
			printArgs[i] = arg
		}
		logger.Info("%s", fmt.Sprintln(printArgs...))
		return goja.Undefined()
	}); err != nil {
		return err
	}
	if err := vm.GlobalObject().Set("alert", func(call goja.FunctionCall) goja.Value {
		printArgs := make([]any, len(call.Arguments))
		for i, arg := range call.Arguments {
			printArgs[i] = arg
		}
		logger.Error("%s", fmt.Sprintln(printArgs...))
		return goja.Undefined()
	}); err != nil {
		return err
	}
	return nil
}
