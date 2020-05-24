package main

import (
    "net/http"
    "net/url"
    "errors"
    "strings"
    "strconv"
    "encoding/base64"
    "crypto/subtle"
)

const AUTH_REQUIRED_MSG = "Proxy authentication required."

type Auth interface {
    Validate(wr http.ResponseWriter, req *http.Request) bool
}

func NewAuth(paramstr string) (Auth, error) {
    url, err := url.Parse(paramstr)
    if err != nil {
        return nil, err
    }

    switch strings.ToLower(url.Scheme) {
    case "static":
        auth, err := NewStaticAuth(url)
        return auth, err
    case "none":
        return NoAuth{}, nil
    default:
        return nil, errors.New("Unknown auth scheme")
    }
}

type StaticAuth struct {
    token string
    hiddenDomain string
}

func NewStaticAuth(param_url *url.URL) (*StaticAuth, error) {
    values, err := url.ParseQuery(param_url.RawQuery)
    if err != nil {
        return nil, err
    }
    username := values.Get("username")
    if username == "" {
        return nil, errors.New("\"username\" parameter is missing from auth config URI")
    }
    password := values.Get("password")
    if password == "" {
        return nil, errors.New("\"password\" parameter is missing from auth config URI")
    }
    return &StaticAuth{
        token: base64.StdEncoding.EncodeToString([]byte(username + ":" + password)),
        hiddenDomain: strings.ToLower(values.Get("hidden_domain")),
    }, nil
}

func requireBasicAuth(wr http.ResponseWriter, req *http.Request, hidden_domain string) {
    if hidden_domain != "" &&
        (subtle.ConstantTimeCompare([]byte(req.URL.Host), []byte(hidden_domain)) != 1 &&
        subtle.ConstantTimeCompare([]byte(req.Host), []byte(hidden_domain)) != 1) {
        http.Error(wr, "Bad Request", http.StatusBadRequest)
    } else {
        wr.Header().Set("Proxy-Authenticate", `Basic realm="dumbproxy"`)
        wr.Header().Set("Content-Length", strconv.Itoa(len([]byte(AUTH_REQUIRED_MSG))))
        wr.WriteHeader(407)
        wr.Write([]byte(AUTH_REQUIRED_MSG))
    }
}

func (auth *StaticAuth) Validate(wr http.ResponseWriter, req *http.Request) bool {
    hdr := req.Header.Get("Proxy-Authorization")
    if hdr == "" {
        requireBasicAuth(wr, req, auth.hiddenDomain)
        return false
    }
    hdr_parts := strings.SplitN(hdr, " ", 2)
    if len(hdr_parts) != 2 || strings.ToLower(hdr_parts[0]) != "basic" {
        requireBasicAuth(wr, req, auth.hiddenDomain)
        return false
    }
    token := hdr_parts[1]
    ok := (subtle.ConstantTimeCompare([]byte(token), []byte(auth.token)) == 1)
    if ok {
        if auth.hiddenDomain != "" &&
            (req.Host == auth.hiddenDomain || req.URL.Host == auth.hiddenDomain) {
            http.Error(wr, "Browser auth triggered!", http.StatusGone)
            return false
        } else {
            return true
        }
    } else {
        requireBasicAuth(wr, req, auth.hiddenDomain)
        return false
    }
}

type NoAuth struct {}

func (_ NoAuth) Validate(wr http.ResponseWriter, req *http.Request) bool {
    return true
}

