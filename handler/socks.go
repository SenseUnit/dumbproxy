package handler

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"

	ddto "github.com/SenseUnit/dumbproxy/dialer/dto"
	clog "github.com/SenseUnit/dumbproxy/log"
	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

func SOCKSHandler(dialer HandlerDialer, logger *clog.CondLogger, forward ForwardFunc) func(ctx context.Context, writer io.Writer, request *socks5.Request) error {
	var (
		outboundMux sync.RWMutex
	)
	outbound := make(map[string]string)
	isLoopback := func(addr string) (string, bool) {
		outboundMux.RLock()
		defer outboundMux.RUnlock()
		originator, ok := outbound[addr]
		return originator, ok
	}
	return func(ctx context.Context, writer io.Writer, request *socks5.Request) error {
		if originator, isLoopback := isLoopback(request.RemoteAddr.String()); isLoopback {
			logger.Critical("Loopback tunnel detected: %s is an outbound "+
				"address for another request from %s", request.RemoteAddr.String(), originator)
			socks5.SendReply(writer, statute.RepConnectionRefused, nil)
			return fmt.Errorf("Loopback tunnel detected: %s is an outbound "+
				"address for another request from %s", request.RemoteAddr.String(), originator)
		}
		username := ""
		if request.AuthContext != nil {
			username = request.AuthContext.Payload["username"]
		}
		localAddr := request.LocalAddr.String()
		ctx = ddto.BoundDialerParamsToContext(ctx, nil, trimAddrPort(localAddr))
		ctx = ddto.FilterParamsToContext(ctx, nil, username)
		logger.Info("Request: %v => %v %q %v %v %v", request.RemoteAddr, localAddr, username, "SOCKS5", "CONNECT", request.DestAddr)
		target, err := dialer.DialContext(ctx, "tcp", request.DestAddr.String())
		if err != nil {
			msg := err.Error()
			resp := statute.RepHostUnreachable
			if strings.Contains(msg, "refused") {
				resp = statute.RepConnectionRefused
			} else if strings.Contains(msg, "network is unreachable") {
				resp = statute.RepNetworkUnreachable
			}
			if err := socks5.SendReply(writer, resp, nil); err != nil {
				return fmt.Errorf("failed to send reply: %w", err)
			}
			return fmt.Errorf("connect to %v failed: %w", request.RawDestAddr, err)
		}
		outboundMux.Lock()
		outbound[target.LocalAddr().String()] = request.RemoteAddr.String()
		outboundMux.Unlock()
		defer func() {
			target.Close() // nolint: errcheck
			outboundMux.Lock()
			delete(outbound, localAddr)
			outboundMux.Unlock()
		}()

		// Send success
		if err := socks5.SendReply(writer, statute.RepSuccess, target.LocalAddr()); err != nil {
			return fmt.Errorf("failed to send reply, %v", err)
		}

		return forward(ctx, username, wrapSOCKS(request.Reader, writer), target)
	}
}
