package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/dop251/goja"

	"github.com/SenseUnit/dumbproxy/dialer/dto"
	"github.com/SenseUnit/dumbproxy/jsext"
	clog "github.com/SenseUnit/dumbproxy/log"
)

type JSRouterFunc = func(req *jsext.JSRequestInfo, dst *jsext.JSDstInfo, username string) (string, error)

type JSRouter struct {
	funcPool     chan JSRouterFunc
	proxyFactory func(string) (Dialer, error)
	next         Dialer
}

func NewJSRouter(filename string, instances int, factory func(string) (Dialer, error), logger *clog.CondLogger, next Dialer) (*JSRouter, error) {
	script, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("unable to load JS script file %q: %w", filename, err)
	}

	instances = max(1, instances)
	pool := make(chan JSRouterFunc, instances)

	for i := 0; i < instances; i++ {
		vm := goja.New()
		err := jsext.AddPrinter(vm, logger)
		if err != nil {
			return nil, fmt.Errorf("can't add print function to runtime: %w", err)
		}
		err = jsext.ConfigureRuntime(vm)
		if err != nil {
			return nil, fmt.Errorf("can't configure runtime runtime: %w", err)
		}
		vm.SetFieldNameMapper(goja.TagFieldNameMapper("json", true))
		_, err = vm.RunString(string(script))
		if err != nil {
			return nil, fmt.Errorf("script run failed: %w", err)
		}

		var f JSRouterFunc
		var routerFnJSVal goja.Value
		if ex := vm.Try(func() {
			routerFnJSVal = vm.Get("getProxy")
		}); ex != nil {
			return nil, fmt.Errorf("\"getProxy\" function cannot be located in VM context: %w", err)
		}
		if routerFnJSVal == nil {
			return nil, errors.New("\"getProxy\" function is not defined")
		}
		err = vm.ExportTo(routerFnJSVal, &f)
		if err != nil {
			return nil, fmt.Errorf("can't export \"getProxy\" function from JS VM: %w", err)
		}

		pool <- f
	}

	return &JSRouter{
		funcPool:     pool,
		proxyFactory: factory,
		next:         next,
	}, nil
}

func (j *JSRouter) getNextDialer(ctx context.Context, network, address string) (Dialer, error) {
	req, username := dto.FilterParamsFromContext(ctx)
	ri := jsext.JSRequestInfoFromRequest(req)
	di, err := jsext.JSDstInfoFromContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("unable to construct dst info: %w", err)
	}

	var res string
	func() {
		f := <-j.funcPool
		defer func(pool chan JSRouterFunc, f JSRouterFunc) {
			pool <- f
		}(j.funcPool, f)
		res, err = f(ri, di, username)
	}()
	if err != nil {
		return nil, fmt.Errorf("JS routing script exception: %w", err)
	}

	if res == "" {
		return j.next, nil
	}

	d, err := j.proxyFactory(res)
	if err != nil {
		return nil, fmt.Errorf("proxy factory returned error: %w", err)
	}
	return d, nil
}

func (j *JSRouter) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d, err := j.getNextDialer(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("unable to route request: %w", err)
	}
	return d.DialContext(ctx, network, address)
}

func (j *JSRouter) WantsHostname(ctx context.Context, network, address string) bool {
	d, err := j.getNextDialer(ctx, network, address)
	if err != nil {
		return false
	}
	return WantsHostname(ctx, network, address, d)
}

func (j *JSRouter) Dial(network, address string) (net.Conn, error) {
	panic("dialer tree linking issue: JSFilter should never receive calls without context")
}

var _ Dialer = new(JSRouter)
var _ HostnameWanter = new(JSRouter)
