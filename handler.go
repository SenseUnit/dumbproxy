package main

import (
    "net"
    "fmt"
    "time"
    "net/http"
    "strings"
    "context"
)

type ProxyHandler struct {
    timeout time.Duration
    auth Auth
    logger *CondLogger
    httptransport http.RoundTripper
}

func NewProxyHandler(timeout time.Duration, auth Auth, logger *CondLogger) *ProxyHandler {
	httptransport := &http.Transport{}
    return &ProxyHandler{
        timeout: timeout,
        auth: auth,
        logger: logger,
        httptransport: httptransport,
    }
}

func (s *ProxyHandler) HandleTunnel(wr http.ResponseWriter, req *http.Request) {
    ctx, _ := context.WithTimeout(req.Context(), s.timeout)
    dialer := net.Dialer{}
    conn, err := dialer.DialContext(ctx, "tcp", req.RequestURI)
    if err != nil {
        s.logger.Error("Can't satisfy CONNECT request: %v", err)
        http.Error(wr, "Can't satisfy CONNECT request", http.StatusBadGateway)
        return
    }
    defer conn.Close()

    if req.ProtoMajor == 0 || req.ProtoMajor == 1 {
        // Upgrade client connection
        localconn, _, err := hijack(wr)
        if err != nil {
            s.logger.Error("Can't hijack client connection: %v", err)
            http.Error(wr, "Can't hijack client connection", http.StatusInternalServerError)
            return
        }
        defer localconn.Close()

        // Inform client connection is built
        fmt.Fprintf(localconn, "HTTP/%d.%d 200 OK\r\n\r\n", req.ProtoMajor, req.ProtoMinor)

        proxy(req.Context(), localconn, conn)
    } else if req.ProtoMajor == 2 {
        wr.Header()["Date"] = nil
        wr.WriteHeader(http.StatusOK)
        flush(wr)
        proxyh2(req.Context(), req.Body, wr, conn)
    } else {
        s.logger.Error("Unsupported protocol version: %s", req.Proto)
        http.Error(wr, "Unsupported protocol version.", http.StatusBadRequest)
        return
    }
}

func (s *ProxyHandler) HandleRequest(wr http.ResponseWriter, req *http.Request) {
    req.RequestURI = ""
    if req.ProtoMajor == 2 {
        req.URL.Scheme = "http" // We can't access :scheme pseudo-header, so assume http
        req.URL.Host = req.Host
    }
    resp, err := s.httptransport.RoundTrip(req)
    if err != nil {
        s.logger.Error("HTTP fetch error: %v", err)
        http.Error(wr, "Server Error", http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()
    s.logger.Info("%v %v %v %v", req.RemoteAddr, req.Method, req.URL, resp.Status)
    delHopHeaders(resp.Header)
    copyHeader(wr.Header(), resp.Header)
    wr.WriteHeader(resp.StatusCode)
    flush(wr)
    copyBody(wr, resp.Body)
}

func (s *ProxyHandler) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	s.logger.Info("Request: %v %v %v %v", req.RemoteAddr, req.Proto, req.Method, req.URL)
    isConnect := strings.ToUpper(req.Method) == "CONNECT"
    if (req.URL.Host == "" || req.URL.Scheme == "" && !isConnect) && req.ProtoMajor < 2 ||
        req.Host == "" && req.ProtoMajor == 2 {
        http.Error(wr, "Bad Request", http.StatusBadRequest)
        return
    }
    if !s.auth.Validate(wr, req) {
        return
    }
    delHopHeaders(req.Header)
    if isConnect {
        s.HandleTunnel(wr, req)
    } else {
        s.HandleRequest(wr, req)
    }
}
