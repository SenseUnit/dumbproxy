package jsext

import (
	"regexp"
	"strings"

	"github.com/dop251/goja"
)

func AddShExpMatch(vm *goja.Runtime) error {
	return vm.GlobalObject().Set("shExpMatch", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 2 {
			return vm.ToValue(false)
		}
		str := call.Argument(0).String()
		pattern := regexp.QuoteMeta(call.Argument(1).String())
		pattern = strings.ReplaceAll(pattern, "\\*", ".*")
		pattern = strings.ReplaceAll(pattern, "\\?", ".")
		matcher, err := regexp.Compile("^" + pattern + "$")
		if err != nil {
			panic(vm.NewGoError(err))
		}
		return vm.ToValue(matcher.MatchString(str))
	})
}
