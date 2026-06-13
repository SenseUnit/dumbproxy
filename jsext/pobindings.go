package jsext

import (
	"github.com/dop251/goja"
)

func AddPOBindings(vm *goja.Runtime) error {
	po := vm.NewObject()
	if err := po.Set("bindings", vm.NewObject()); err != nil {
		return err
	}
	return vm.GlobalObject().Set("ProxyObject", po)
}
