package auth

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strconv"
	"strings"
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
