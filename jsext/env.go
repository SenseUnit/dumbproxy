package jsext

import (
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/dop251/goja"
)

var (
	createEnvObjectOnce sync.Once
	envObject           *goja.Object
)

type readonlyEnvObject struct {
	m map[string]goja.String
	k []string
}

func (o *readonlyEnvObject) Get(key string) goja.Value {
	v, ok := o.m[key]
	if ok {
		return v
	}
	return goja.Undefined()
}

func (o *readonlyEnvObject) Set(_ string, _ goja.Value) bool {
	return false
}

func (o *readonlyEnvObject) Has(key string) bool {
	_, ok := o.m[key]
	return ok
}

func (o *readonlyEnvObject) Delete(key string) bool {
	return false
}

func (o *readonlyEnvObject) Keys() []string {
	return o.k
}

func createEnvObject() *goja.Object {
	env := os.Environ()
	m := make(map[string]goja.String, len(env))
	k := make([]string, 0, len(env))
	for _, pair := range env {
		key, value, _ := strings.Cut(pair, "=")
		sb := new(goja.StringBuilder)
		sb.WriteUTF8String(value)
		m[key] = sb.String()
		k = append(k, key)
	}
	slices.Sort(k)
	return goja.NewSharedDynamicObject(&readonlyEnvObject{
		m: m,
		k: k,
	})
}

func GetEnvSharedDynamicObject() *goja.Object {
	createEnvObjectOnce.Do(func() {
		envObject = createEnvObject()
	})
	return envObject
}

func ExportEnv(vm *goja.Runtime) error {
	return vm.Set("env", GetEnvSharedDynamicObject())
}
