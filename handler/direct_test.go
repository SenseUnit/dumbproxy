package handler

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	derrors "github.com/SenseUnit/dumbproxy/dialer/errors"
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
	proxy := NewProxyHandler(&Config{
		Dialer:       deniedDialer{},
		AccessReject: staticReject{status: http.StatusTeapot, body: "access response"},
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
}
