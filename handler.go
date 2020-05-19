package main

import (
    "io"
    "net"
    "fmt"
    "net/http"
    "strings"
)

type ProxyHandler struct {
    logger *CondLogger
    httptransport http.RoundTripper
}

func NewProxyHandler(logger *CondLogger) *ProxyHandler {
	httptransport := &http.Transport{}
    return &ProxyHandler{
        logger: logger,
        httptransport: httptransport,
    }
}

func (s *ProxyHandler) HandleTunnel(wr http.ResponseWriter, req *http.Request) {
    conn, err := net.Dial("tcp", req.RequestURI)
    if err != nil {
        s.logger.Error("Can't satisfy CONNECT request: %v", err)
        http.Error(wr, "Can't satisfy CONNECT request", http.StatusBadGateway)
        return
    }
    defer conn.Close()


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
}

func (s *ProxyHandler) HandleRequest(wr http.ResponseWriter, req *http.Request) {
    req.RequestURI = ""
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
    io.Copy(wr, resp.Body)
}

func (s *ProxyHandler) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	s.logger.Info("Request: %v %v %v", req.RemoteAddr, req.Method, req.URL)
    delHopHeaders(req.Header)
    if strings.ToUpper(req.Method) == "CONNECT" {
        s.HandleTunnel(wr, req)
    } else {
        s.HandleRequest(wr, req)
    }
}
