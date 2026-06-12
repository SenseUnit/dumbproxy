package jsext

import (
	"fmt"

	"github.com/dop251/goja"
)

type vmInitPart = func(vm *goja.Runtime) error

func ConfigureRuntime(vm *goja.Runtime) error {
	for idx, f := range []vmInitPart{
		func(vm *goja.Runtime) error {
			vm.SetFieldNameMapper(goja.TagFieldNameMapper("json", true))
			return nil
		},
		AddFileReader,
		AddStopAddressIteration,
		AddMMDBReader,
		ExportEnv,
		AddConvertAddr,
		AddShExpMatch,
	} {
		if err := f(vm); err != nil {
			return fmt.Errorf("JS runtime init part #%d failed: %w", idx+1, err)
		}
	}
	return nil
}
