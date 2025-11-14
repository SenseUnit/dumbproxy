package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	clog "github.com/SenseUnit/dumbproxy/log"
)

type Auth interface {
	Validate(ctx context.Context, wr http.ResponseWriter, req *http.Request) (string, bool)
	Stop()
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
		return NewRejectHTTPAuth(url, logger)
	default:
		return nil, errors.New("Unknown auth scheme")
	}
}
