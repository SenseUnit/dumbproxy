package handler

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	derrors "github.com/SenseUnit/dumbproxy/dialer/errors"
	clog "github.com/SenseUnit/dumbproxy/log"
)

type staticReject struct {
	status int
	body   string
}

func (r staticReject) Validate(_ context.Context, wr http.ResponseWriter, _ *http.Request) (string, bool) {
	wr.WriteHeader(r.status)
	_, _ = wr.Write([]byte(r.body))
	return "", false
}

func (staticReject) Close() error {
	return nil
}

type deniedDialer struct{}

func (deniedDialer) DialContext(_ context.Context, _, _ string) (net.Conn, error) {
	return nil, derrors.ErrAccessDenied{Err: errors.New("denied")}
}

func TestIsDirectRequest(t *testing.T) {
	tests := []struct {
		name string
		req  *http.Request
		want bool
	}{
		{
			name: "origin form get",
			req: &http.Request{
				Method: http.MethodGet,
				URL:    &url.URL{Path: "/"},
				Host:   "web.nacl.one",
			},
			want: true,
		},
		{
			name: "absolute form get",
			req: &http.Request{
				Method: http.MethodGet,
				URL:    &url.URL{Scheme: "http", Host: "openrouter.ai", Path: "/"},
				Host:   "openrouter.ai",
			},
			want: false,
		},
		{
			name: "connect",
			req: &http.Request{
				Method: http.MethodConnect,
				URL:    &url.URL{Host: "openrouter.ai:443"},
				Host:   "openrouter.ai:443",
			},
			want: false,
		},
		{
			name: "trust tunnel random",
			req: &http.Request{
				Method: "GETRANDOM",
				URL:    &url.URL{Path: "/32"},
				Host:   "web.nacl.one",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDirectRequest(tt.req); got != tt.want {
				t.Fatalf("isDirectRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDirectResponse(t *testing.T) {
	proxy := NewProxyHandler(&Config{
		DirectResponse: staticReject{status: http.StatusOK, body: "direct response"},
	})
	rr := httptest.NewRecorder()
	req := &http.Request{
		Method:     http.MethodGet,
		URL:        &url.URL{Path: "/"},
		Host:       "web.nacl.one",
		RemoteAddr: "198.51.100.7:1234",
	}

	proxy.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if rr.Body.String() != "direct response" {
		t.Fatalf("body = %q, want direct response", rr.Body.String())
	}
}

func TestAccessReject(t *testing.T) {
	var logBuf bytes.Buffer
	proxy := NewProxyHandler(&Config{
		Dialer:       deniedDialer{},
		AccessReject: staticReject{status: http.StatusTeapot, body: "access response"},
		Logger:       clog.NewCondLogger(log.New(&logBuf, "", 0), clog.INFO),
	})
	rr := httptest.NewRecorder()
	req := &http.Request{
		Method:     http.MethodConnect,
		URL:        &url.URL{Host: "openrouter.ai:443"},
		RequestURI: "openrouter.ai:443",
		Host:       "openrouter.ai:443",
		RemoteAddr: "198.51.100.7:1234",
		ProtoMajor: 1,
	}

	proxy.ServeHTTP(rr, req)

	if rr.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusTeapot)
	}
	if rr.Body.String() != "access response" {
		t.Fatalf("body = %q, want access response", rr.Body.String())
	}

	logOutput := logBuf.String()
	if got := strings.Count(logOutput, "INFO     Request:"); got != 1 {
		t.Fatalf("INFO Request log count = %d, want 1\nlogs:\n%s", got, logOutput)
	}
	if !strings.Contains(logOutput, "CONNECT openrouter.ai:443 418 I'm a teapot dur=") {
		t.Fatalf("access log is missing status or duration\nlogs:\n%s", logOutput)
	}
}
