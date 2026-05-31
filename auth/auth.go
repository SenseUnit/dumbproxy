package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	clog "github.com/SenseUnit/dumbproxy/log"
)

type Auth interface {
	Validate(ctx context.Context, wr http.ResponseWriter, req *http.Request) (string, bool)
	io.Closer
}

func NewAuth(paramstr string, logger *clog.CondLogger) (Auth, error) {
	url, err := url.Parse(paramstr)
	if err != nil {
		return nil, err
	}

	switch strings.ToLower(url.Scheme) {
	case "static":
		return NewStaticAuth(url, logger)
	case "basicfile":
		return NewBasicFileAuth(url, logger)
	case "hmac":
		return NewHMACAuth(url, logger)
	case "cert":
		return NewCertAuth(url, logger)
	case "redis":
		return NewRedisAuth(url, false, logger)
	case "redis-cluster":
		return NewRedisAuth(url, true, logger)
	case "none":
		return NoAuth{}, nil
	case "reject-http", "reject-https":
		return newRejectAuthFromURL(url, logger)
	case "reject-static":
		return newRejectAuthFromURL(url, logger)
	case "tlscookie":
		return NewTLSCookieAuth(url, logger)
	default:
		return nil, fmt.Errorf("unknown auth scheme %q", url.Scheme)
	}
}

// NewRejectAuth constructs an auth provider which always responds and rejects.
func NewRejectAuth(paramstr string, logger *clog.CondLogger) (Auth, error) {
	url, err := url.Parse(paramstr)
	if err != nil {
		return nil, err
	}

	return newRejectAuthFromURL(url, logger)
}

func newRejectAuthFromURL(url *url.URL, logger *clog.CondLogger) (Auth, error) {
	switch strings.ToLower(url.Scheme) {
	case "reject-http", "reject-https":
		return NewRejectHTTPAuth(url, logger)
	case "reject-static":
		return NewStaticRejectAuth(url, logger)
	default:
		return nil, errors.New("Unknown reject scheme")
	}
}

func NewResponse(paramstr string, logger *clog.CondLogger) (Auth, error) {
	url, err := url.Parse(paramstr)
	if err != nil {
		return nil, err
	}

	switch strings.ToLower(url.Scheme) {
	case "static":
		return NewStaticResponse(url, logger)
	default:
		return nil, errors.New("Unknown response scheme")
	}
}
