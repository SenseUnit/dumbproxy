package jsext

import (
	"fmt"
	"strings"
	"time"

	"github.com/dop251/goja"
)

func parseWD(s string) (time.Weekday, error) {
	switch s {
	case "SUN":
		return time.Sunday, nil
	case "MON":
		return time.Monday, nil
	case "TUE":
		return time.Tuesday, nil
	case "WED":
		return time.Wednesday, nil
	case "THU":
		return time.Thursday, nil
	case "FRI":
		return time.Friday, nil
	case "SAT":
		return time.Saturday, nil
	default:
		return 0, fmt.Errorf("unable to parse week day name: %q", s)
	}
}

func wdRange(vm *goja.Runtime, a, b string, gmt bool) goja.Value {
	a = strings.ToUpper(a)
	b = strings.ToUpper(b)
	an, err := parseWD(a)
	if err != nil {
		panic(vm.NewGoError(err))
	}
	bn, err := parseWD(b)
	if err != nil {
		panic(vm.NewGoError(err))
	}
	if an > bn {
		an, bn = bn, an
	}
	t := time.Now()
	if gmt {
		t = t.UTC()
	}
	wd := t.Weekday()
	return vm.ToValue(wd >= an && wd <= bn)
}

func AddWeekdayRange(vm *goja.Runtime) error {
	return vm.GlobalObject().Set("weekdayRange", func(call goja.FunctionCall) goja.Value {
		switch len(call.Arguments) {
		case 0:
			panic(vm.NewTypeError("weekdayRange expects at least one argument"))
		case 1:
			return wdRange(vm, call.Argument(0).String(), call.Argument(0).String(), false)
		case 2:
			if call.Argument(1).String() == "GMT" {
				return wdRange(vm, call.Argument(0).String(), call.Argument(0).String(), true)
			} else {
				return wdRange(vm, call.Argument(0).String(), call.Argument(1).String(), false)
			}
		default:
			if call.Argument(2).String() == "GMT" {
				return wdRange(vm, call.Argument(0).String(), call.Argument(1).String(), true)
			} else {
				return wdRange(vm, call.Argument(0).String(), call.Argument(1).String(), false)
			}
		}
	})
}
