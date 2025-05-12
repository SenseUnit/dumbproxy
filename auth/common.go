package auth

import (
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/tg123/go-htpasswd"
)

func matchHiddenDomain(host, hidden_domain string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)
	return subtle.ConstantTimeCompare([]byte(host), []byte(hidden_domain)) == 1
}

func requireBasicAuth(wr http.ResponseWriter, req *http.Request, hidden_domain string) {
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
