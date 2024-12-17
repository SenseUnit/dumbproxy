package handler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/SenseUnit/dumbproxy/auth"
	"github.com/SenseUnit/dumbproxy/dialer"
	ddto "github.com/SenseUnit/dumbproxy/dialer/dto"
	derrors "github.com/SenseUnit/dumbproxy/dialer/errors"
	"github.com/SenseUnit/dumbproxy/forward"
	clog "github.com/SenseUnit/dumbproxy/log"
)

const HintsHeaderName = "X-Src-IP-Hints"

type HandlerDialer interface {
	DialContext(ctx context.Context, net, address string) (net.Conn, error)
}

type ProxyHandler struct {
	auth          auth.Auth
	logger        *clog.CondLogger
	dialer        HandlerDialer
	forward       func(ctx context.Context, username string, incoming, outgoing io.ReadWriteCloser) error
	httptransport http.RoundTripper
	outbound      map[string]string
	outboundMux   sync.RWMutex
	userIPHints   bool
}

func NewProxyHandler(config *Config) *ProxyHandler {
	d := config.Dialer
	if d == nil {
		d = dialer.NewBoundDialer(nil, "")
	}
	httptransport := &http.Transport{
		DialContext:       d.DialContext,
		DisableKeepAlives: true,
	}
	a := config.Auth
	if a == nil {
		a = auth.NoAuth{}
	}
	l := config.Logger
	if l == nil {
		l = clog.NewCondLogger(log.New(io.Discard, "", 0), 0)
	}
	f := config.Forward
	if f == nil {
		f = forward.PairConnections
	}
	return &ProxyHandler{
		auth:          a,
		logger:        l,
		dialer:        d,
		forward:       f,
		httptransport: httptransport,
		outbound:      make(map[string]string),
		userIPHints:   config.UserIPHints,
	}
}

func (s *ProxyHandler) HandleTunnel(wr http.ResponseWriter, req *http.Request, username string) {
	conn, err := s.dialer.DialContext(req.Context(), "tcp", req.RequestURI)
	if err != nil {
		var accessErr derrors.ErrAccessDenied
		if errors.As(err, &accessErr) {
			s.logger.Warning("Access denied: %v", err)
			http.Error(wr, "Access denied", http.StatusForbidden)
			return
		}
		s.logger.Error("Can't satisfy CONNECT request: %v", err)
		http.Error(wr, "Can't satisfy CONNECT request", http.StatusBadGateway)
		return
	}

	localAddr := conn.LocalAddr().String()
	s.outboundMux.Lock()
	s.outbound[localAddr] = req.RemoteAddr
	s.outboundMux.Unlock()
	defer func() {
		conn.Close()
		s.outboundMux.Lock()
		delete(s.outbound, localAddr)
		s.outboundMux.Unlock()
	}()

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

		s.forward(req.Context(), username, localconn, conn)
	} else if req.ProtoMajor == 2 {
		wr.Header()["Date"] = nil
		wr.WriteHeader(http.StatusOK)
		flush(wr)
		s.forward(req.Context(), username, wrapH2(req.Body, wr), conn)
	} else {
		s.logger.Error("Unsupported protocol version: %s", req.Proto)
		http.Error(wr, "Unsupported protocol version.", http.StatusBadRequest)
		return
	}
}

func (s *ProxyHandler) HandleRequest(wr http.ResponseWriter, req *http.Request, username string) {
	req.RequestURI = ""
	forwardReqBody := newH1ReqBodyPipe()
	origBody := req.Body
	req.Body = forwardReqBody.Body()
	go func() {
		s.forward(req.Context(), username, wrapH1ReqBody(origBody), forwardReqBody)
	}()
	if req.ProtoMajor == 2 {
		req.URL.Scheme = "http" // We can't access :scheme pseudo-header, so assume http
		req.URL.Host = req.Host
	}
	resp, err := s.httptransport.RoundTrip(req)
	if err != nil {
		var accessErr derrors.ErrAccessDenied
		if errors.As(err, &accessErr) {
			s.logger.Warning("Access denied: %v", err)
			http.Error(wr, "Access denied", http.StatusForbidden)
			return
		}
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
	s.forward(req.Context(), username, wrapH1RespWriter(wr), wrapH1ReqBody(resp.Body))
}

func (s *ProxyHandler) isLoopback(req *http.Request) (string, bool) {
	s.outboundMux.RLock()
	originator, found := s.outbound[req.RemoteAddr]
	s.outboundMux.RUnlock()
	return originator, found
}

func (s *ProxyHandler) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	if originator, isLoopback := s.isLoopback(req); isLoopback {
		s.logger.Critical("Loopback tunnel detected: %s is an outbound "+
			"address for another request from %s", req.RemoteAddr, originator)
		http.Error(wr, auth.BAD_REQ_MSG, http.StatusBadRequest)
		return
	}

	isConnect := strings.ToUpper(req.Method) == "CONNECT"
	if (req.URL.Host == "" || req.URL.Scheme == "" && !isConnect) && req.ProtoMajor < 2 ||
		req.Host == "" && req.ProtoMajor == 2 {
		http.Error(wr, auth.BAD_REQ_MSG, http.StatusBadRequest)
		return
	}

	username, ok := s.auth.Validate(wr, req)
	localAddr := getLocalAddr(req.Context())
	s.logger.Info("Request: %v => %v %q %v %v %v", req.RemoteAddr, localAddr, username, req.Proto, req.Method, req.URL)

	if !ok {
		return
	}

	var ipHints *string
	if s.userIPHints {
		hintValues := req.Header.Values(HintsHeaderName)
		if len(hintValues) > 0 {
			req.Header.Del(HintsHeaderName)
			ipHints = &hintValues[0]
		}
	}
	ctx := req.Context()
	ctx = ddto.BoundDialerParamsToContext(ctx, ipHints, trimAddrPort(localAddr))
	ctx = ddto.FilterParamsToContext(ctx, req, username)
	req = req.WithContext(ctx)
	delHopHeaders(req.Header)
	if isConnect {
		s.HandleTunnel(wr, req, username)
	} else {
		s.HandleRequest(wr, req, username)
	}
}

func trimAddrPort(addrPort string) string {
	res, _, err := net.SplitHostPort(addrPort)
	if err != nil {
		return addrPort
	}
	return res
}

func getLocalAddr(ctx context.Context) string {
	if addr, ok := ctx.Value(http.LocalAddrContextKey).(net.Addr); ok {
		return addr.String()
	}
	return "<request context is missing address>"
}
