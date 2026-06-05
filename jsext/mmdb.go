package jsext

import (
	"net/netip"
	"runtime"

	"github.com/dop251/goja"
	"github.com/oschwald/maxminddb-golang/v2"
)

type mmdbReaderObject struct {
	reader *maxminddb.Reader
	vm     *goja.Runtime
}

func (ro *mmdbReaderObject) Get(key string) goja.Value {
	switch key {
	case "lookup":
		return ro.vm.ToValue(ro.jsLookup)
	default:
		return goja.Undefined()
	}
}

func (ro *mmdbReaderObject) Set(_ string, _ goja.Value) bool {
	return false
}

func (ro *mmdbReaderObject) Has(key string) bool {
	return key == "lookup"
}

func (ro *mmdbReaderObject) Delete(key string) bool {
	return false
}

func (ro *mmdbReaderObject) Keys() []string {
	return []string{"lookup"}
}

func (ro *mmdbReaderObject) lookup(ip netip.Addr) (any, error) {
	var record any
	err := ro.reader.Lookup(ip).Decode(&record)
	if err != nil {
		return nil, err
	}
	return record, nil
}

func (ro *mmdbReaderObject) jsLookup(call goja.FunctionCall, vm *goja.Runtime) goja.Value {
	if len(call.Arguments) != 1 {
		panic(vm.NewTypeError("lookup expects exactly 1 argument, IP address string"))
	}
	ip, err := netip.ParseAddr(call.Argument(0).String())
	if err != nil {
		panic(vm.NewGoError(err))
	}
	record, err := ro.lookup(ip)
	if err != nil {
		panic(vm.NewGoError(err))
	}
	return vm.ToValue(record)
}

func newMMDBReaderObject(reader *maxminddb.Reader, vm *goja.Runtime) *mmdbReaderObject {
	o := &mmdbReaderObject{
		reader: reader,
		vm:     vm,
	}
	runtime.AddCleanup(o, func(r *maxminddb.Reader) {
		r.Close()
	}, reader)
	return o
}

func mmdbOpen(filename string, vm *goja.Runtime) (*mmdbReaderObject, error) {
	reader, err := maxminddb.Open(filename)
	if err != nil {
		return nil, err
	}
	return newMMDBReaderObject(reader, vm), nil
}

func AddMMDBReader(vm *goja.Runtime) error {
	return vm.GlobalObject().Set("mmdbOpen", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) != 1 {
			panic(vm.NewTypeError("mmdbOpen expects exactly 1 argument, a filename"))
		}

		filename := call.Argument(0).String()
		ro, err := mmdbOpen(filename, vm)
		if err != nil {
			panic(vm.NewGoError(err))
		}

		return vm.NewDynamicObject(ro)
	})
}
