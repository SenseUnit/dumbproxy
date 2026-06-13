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

func AddDNSDomainIs(vm *goja.Runtime) error {
	return vm.GlobalObject().Set("dnsDomainIs", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 2 {
			return vm.ToValue(false)
		}
		host := strings.ToLower(call.Argument(0).String())
		domain := strings.ToLower(call.Argument(1).String())
		if host == domain {
			return vm.ToValue(true)
		}
		if !strings.HasPrefix(domain, ".") {
			domain = "." + domain
		}
		return vm.ToValue(strings.HasSuffix(host, domain))
	})
}

func AddLocalHostOrDomainIs(vm *goja.Runtime) error {
	return vm.GlobalObject().Set("localHostOrDomainIs", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 2 {
			return vm.ToValue(false)
		}
		host := strings.ToLower(call.Argument(0).String())
		domain := strings.ToLower(call.Argument(1).String())
		if host == domain {
			return vm.ToValue(true)
		}
		if strings.Contains(host, ".") {
			return vm.ToValue(false)
		}
		return vm.ToValue(strings.HasPrefix(domain, host+"."))
	})
}

func AddDNSDomainLevels(vm *goja.Runtime) error {
	return vm.GlobalObject().Set("dnsDomainLevels", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 1 {
			return vm.ToValue(0)
		}
		name := call.Argument(0).String()
		name, _ = strings.CutSuffix(name, ".")
		return vm.ToValue(strings.Count(name, "."))
	})
}
