package jsext

import "github.com/dop251/goja"

func ConfigureRuntime(vm *goja.Runtime) error {
	vm.SetFieldNameMapper(goja.TagFieldNameMapper("json", true))
	if err := AddFileReader(vm); err != nil {
		return err
	}
	if err := AddStopAddressIteration(vm); err != nil {
		return err
	}
	if err := ExportEnv(vm); err != nil {
		return err
	}
	return nil
}
