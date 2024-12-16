package access

import (
	"context"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"

	"github.com/dop251/goja"

	clog "github.com/SenseUnit/dumbproxy/log"
)

var ErrJSDenied = errors.New("denied by JS filter")

type JSRequestInfo struct {
	Method           string          `json:"method"`
	URL              string          `json:"url"`
	Proto            string          `json:"proto"`
	ProtoMajor       int             `json:"protoMajor"`
	ProtoMinor       int             `json:"protoMinor"`
	Header           http.Header     `json:"header"`
	ContentLength    int64           `json:"contentLength"`
	TransferEncoding []string        `json:"transferEncoding"`
	Host             string          `json:"host"`
	Form             url.Values      `json:"form"`
	PostForm         url.Values      `json:"portForm"`
	MultipartForm    *multipart.Form `json:"multipartForm"`
	Trailer          http.Header     `json:"trailer"`
	RemoteAddr       string          `json:"remoteAddr"`
	RequestURI       string          `json:"requestURI"`
}

func JSRequestInfoFromRequest(req *http.Request) *JSRequestInfo {
	return &JSRequestInfo{
		Method:           req.Method,
		URL:              req.URL.String(),
		Proto:            req.Proto,
		ProtoMajor:       req.ProtoMajor,
		ProtoMinor:       req.ProtoMinor,
		Header:           req.Header,
		ContentLength:    req.ContentLength,
		TransferEncoding: req.TransferEncoding,
		Host:             req.Host,
		Form:             req.Form,
		PostForm:         req.PostForm,
		MultipartForm:    req.MultipartForm,
		Trailer:          req.Trailer,
		RemoteAddr:       req.RemoteAddr,
		RequestURI:       req.RequestURI,
	}
}

type JSFilterFunc = func(req *JSRequestInfo, username, network, address string) (bool, error)

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
	vm.SetFieldNameMapper(goja.TagFieldNameMapper("json", true))
	err = vm.Set("print", func(call goja.FunctionCall) goja.Value {
		printArgs := make([]interface{}, len(call.Arguments))
		for i, arg := range call.Arguments {
			printArgs[i] = arg
		}
		logger.Info("%s", fmt.Sprintln(printArgs...))
		return goja.Undefined()
	})
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
		vm:     vm,
		f:      f,
		next:   next,
	}, nil
}

func (j *JSFilter) Access(ctx context.Context, req *http.Request, username, network, address string) error {
	ri := JSRequestInfoFromRequest(req)
	res, err := j.f(ri, username, network, address)
	if err != nil {
		return fmt.Errorf("JS access script exception: %w", err)
	}
	if !res {
		return ErrJSDenied
	}
	return j.next.Access(ctx, req, username, network, address)
}
