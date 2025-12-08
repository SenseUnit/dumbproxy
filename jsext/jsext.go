package jsext

import "github.com/dop251/goja"

func ConfigureRuntime(vm *goja.Runtime) error {
	if err := AddFileReader(vm); err != nil {
		return err
	}
	if err := ExportEnv(vm); err != nil {
		return err
	}
	return nil
}
