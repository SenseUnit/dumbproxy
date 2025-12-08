package forward

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/dop251/goja"
	"golang.org/x/sync/errgroup"

	"github.com/SenseUnit/dumbproxy/dialer/dto"
	"github.com/SenseUnit/dumbproxy/jsext"
	clog "github.com/SenseUnit/dumbproxy/log"
)

type JSLimitFunc = func(req *jsext.JSRequestInfo, dst *jsext.JSDstInfo, username string) (*LimitParameters, error)

type JSLimitProvider struct {
	funcPool chan JSLimitFunc
	logger   *clog.CondLogger
}

func NewJSLimitProvider(filename string, instances int, logger *clog.CondLogger) (*JSLimitProvider, error) {
	script, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("unable to load JS script file %q: %w", filename, err)
	}

	instances = max(1, instances)
	pool := make(chan JSLimitFunc, instances)
	initGroup, _ := errgroup.WithContext(context.Background())

	for i := 0; i < instances; i++ {
		initGroup.Go(func() error {
			vm := goja.New()
			err := jsext.AddPrinter(vm, logger)
			if err != nil {
				return fmt.Errorf("can't add print function to runtime: %w", err)
			}
			err = jsext.ConfigureRuntime(vm)
			if err != nil {
				return fmt.Errorf("can't configure runtime: %w", err)
			}
			_, err = vm.RunString(string(script))
			if err != nil {
				return fmt.Errorf("script run failed: %w", err)
			}

			var f JSLimitFunc
			var limitFnJSVal goja.Value
			if ex := vm.Try(func() {
				limitFnJSVal = vm.Get("bwLimit")
			}); ex != nil {
				return fmt.Errorf("\"bwLimit\" function cannot be located in VM context: %w", err)
			}
			if limitFnJSVal == nil {
				return errors.New("\"bwLimit\" function is not defined")
			}
			err = vm.ExportTo(limitFnJSVal, &f)
			if err != nil {
				return fmt.Errorf("can't export \"bwLimit\" function from JS VM: %w", err)
			}

			pool <- f
			return nil
		})
	}

	err = initGroup.Wait()
	if err != nil {
		return nil, err
	}

	return &JSLimitProvider{
		funcPool: pool,
		logger:   logger,
	}, nil
}

func (j *JSLimitProvider) Parameters(ctx context.Context, username, network, address string) (res *LimitParameters, err error) {
	defer func() {
		if err != nil {
			j.logger.Error("%v", err)
		}
	}()
	req, _ := dto.FilterParamsFromContext(ctx)
	ri := jsext.JSRequestInfoFromRequest(req)
	di, err := jsext.JSDstInfoFromContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("unable to construct dst info: %w", err)
	}
	func() {
		f := <-j.funcPool
		defer func(pool chan JSLimitFunc, f JSLimitFunc) {
			pool <- f
		}(j.funcPool, f)
		res, err = f(ri, di, username)
	}()
	if err != nil {
		return nil, fmt.Errorf("JS limit script exception: %w", err)
	}
	if res == nil {
		return nil, fmt.Errorf("JS limit script returned null object")
	}
	return res, nil
}
