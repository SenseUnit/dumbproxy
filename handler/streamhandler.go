package handler

import (
	"context"
	"fmt"
	"net"

	ddto "github.com/SenseUnit/dumbproxy/dialer/dto"
	clog "github.com/SenseUnit/dumbproxy/log"
)

func PortForwardHandler(logger *clog.CondLogger, dialer HandlerDialer, address string, forward ForwardFunc) func(context.Context, net.Conn) {
	return func(ctx context.Context, c net.Conn) {
		if err := func() error {
			defer c.Close()
			username := ""
			localAddr := c.LocalAddr().String()
			ctx = ddto.BoundDialerParamsToContext(ctx, nil, trimAddrPort(localAddr))
			ctx = ddto.FilterParamsToContext(ctx, nil, username)
			logger.Info("Request: %v => %v %q %v %v %v", c.RemoteAddr().String(), localAddr, username, "STREAM", "CONNECT", address)
			target, err := dialer.DialContext(ctx, "tcp", address)
			if err != nil {
				return fmt.Errorf("connect to %s failed: %w", address, err)
			}
			defer target.Close()
			return forward(ctx, username, c, target, "tcp", address)
		}(); err != nil {
			logger.Error("handler failure: %v", err)
		}
	}
}
