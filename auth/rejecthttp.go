package auth

import (
	"context"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	clog "github.com/SenseUnit/dumbproxy/log"
)

type RejectHTTPAuth struct {
	proxy *httputil.ReverseProxy
}

func NewRejectHTTPAuth(u *url.URL, logger *clog.CondLogger) (*RejectHTTPAuth, error) {
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, err
	}
	scheme, _ := strings.CutPrefix(strings.ToLower(u.Scheme), "reject-")
	target := &url.URL{
		Scheme:   scheme,
		User:     u.User,
		Host:     u.Host,
		Path:     u.Path,
		RawPath:  u.RawPath,
		RawQuery: values.Get("qs"),
	}
	xf, _ := strconv.ParseBool(values.Get("x-forwarded"))
	method := values.Get("method")
	return &RejectHTTPAuth{
		proxy: &httputil.ReverseProxy{
			Rewrite: func(r *httputil.ProxyRequest) {
				r.SetURL(target)
				if xf {
					r.SetXForwarded()
				}
				if method != "" {
					r.Out.Method = method
				}
			},
		},
	}, nil
}

func (a *RejectHTTPAuth) Validate(ctx context.Context, w http.ResponseWriter, r *http.Request) (string, bool) {
	r = r.Clone(ctx)
	a.proxy.ServeHTTP(w, r)
	return "", false
}

func (_ *RejectHTTPAuth) Valid(_, _, _ string) bool {
	return false
}

func (_ *RejectHTTPAuth) Close() error {
	return nil
}
