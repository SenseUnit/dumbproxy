package access

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/dop251/goja"

	"github.com/SenseUnit/dumbproxy/jsext"
	clog "github.com/SenseUnit/dumbproxy/log"
)

var ErrJSDenied = errors.New("denied by JS filter")

type JSFilterFunc = func(req *jsext.JSRequestInfo, dst *jsext.JSDstInfo, username string) (bool, error)

// JSFilter is not suitable for concurrent use!
// Wrap it with filter pool for that!
type JSFilter struct {
	vm   *goja.Runtime
	f    JSFilterFunc
	next Filter
}

func NewJSFilter(filename string, logger *clog.CondLogger, next Filter) (*JSFilter, error) {
	script, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("unable to load JS script file %q: %w", filename, err)
	}
	vm := goja.New()
	jsext.AddPrinter(vm, logger)
	vm.SetFieldNameMapper(goja.TagFieldNameMapper("json", true))
	if err != nil {
		return nil, errors.New("can't add print function to runtime")
	}
	_, err = vm.RunString(string(script))
	if err != nil {
		return nil, fmt.Errorf("script run failed: %w", err)
	}

	var f JSFilterFunc
	var accessFnJSVal goja.Value
	if ex := vm.Try(func() {
		accessFnJSVal = vm.Get("access")
	}); ex != nil {
		return nil, fmt.Errorf("\"access\" function cannot be located in VM context: %w", err)
	}
	if accessFnJSVal == nil {
		return nil, errors.New("\"access\" function is not defined")
	}
	err = vm.ExportTo(accessFnJSVal, &f)
	if err != nil {
		return nil, fmt.Errorf("can't export \"access\" function from JS VM: %w", err)
	}

	return &JSFilter{
		vm:   vm,
		f:    f,
		next: next,
	}, nil
}

func (j *JSFilter) Access(ctx context.Context, req *http.Request, username, network, address string) error {
	ri := jsext.JSRequestInfoFromRequest(req)
	di, err := jsext.JSDstInfoFromContext(ctx, network, address)
	if err != nil {
		return fmt.Errorf("unable to construct dst info: %w", err)
	}
	res, err := j.f(ri, di, username)
	if err != nil {
		return fmt.Errorf("JS access script exception: %w", err)
	}
	if !res {
		return ErrJSDenied
	}
	return j.next.Access(ctx, req, username, network, address)
}
