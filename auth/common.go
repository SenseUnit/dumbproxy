package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"

	clog "github.com/SenseUnit/dumbproxy/log"
	"github.com/tg123/go-htpasswd"
)

func matchHiddenDomain(host, hidden_domain string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)
	return subtle.ConstantTimeCompare([]byte(host), []byte(hidden_domain)) == 1
}

func requireBasicAuth(ctx context.Context, wr http.ResponseWriter, req *http.Request, hidden_domain string, next Auth) (string, bool) {
	if next != nil {
		return next.Validate(ctx, wr, req)
	}
	if hidden_domain != "" &&
		!matchHiddenDomain(req.URL.Host, hidden_domain) &&
		!matchHiddenDomain(req.Host, hidden_domain) {
		http.Error(wr, BAD_REQ_MSG, http.StatusBadRequest)
	} else {
		wr.Header().Set("Proxy-Authenticate", `Basic realm="dumbproxy"`)
		wr.Header().Set("Content-Length", strconv.Itoa(len([]byte(AUTH_REQUIRED_MSG))))
		wr.WriteHeader(407)
		wr.Write([]byte(AUTH_REQUIRED_MSG))
	}
	return "", false
}

func tryValid(auth Auth, logger *clog.CondLogger, user, password, userAddr string) bool {
	if validator, ok := auth.(interface {
		Valid(string, string, string) bool
	}); ok {
		return validator.Valid(user, password, userAddr)
	}
	logger.Warning("chained auth provider does not have Valid() method!")
	return false
}

func makePasswdMatcher(encoded string) (htpasswd.EncodedPasswd, error) {
	for _, p := range htpasswd.DefaultSystems {
		matcher, err := p(encoded)
		if err != nil {
			return nil, err
		}
		if matcher != nil {
			return matcher, nil
		}
	}
	return nil, errors.New("no suitable password encoding system found")
}
