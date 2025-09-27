package handler

import (
	"context"
	"fmt"
	"io"
	"strings"

	ddto "github.com/SenseUnit/dumbproxy/dialer/dto"
	clog "github.com/SenseUnit/dumbproxy/log"
	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

func SOCKSHandler(dialer HandlerDialer, logger *clog.CondLogger, forward ForwardFunc) func(ctx context.Context, writer io.Writer, request *socks5.Request) error {
	return func(ctx context.Context, writer io.Writer, request *socks5.Request) error {
		username := ""
		if request.AuthContext != nil {
			username = request.AuthContext.Payload["username"]
		}
		localAddr := request.LocalAddr.String()
		ctx = ddto.BoundDialerParamsToContext(ctx, nil, trimAddrPort(localAddr))
		ctx = ddto.FilterParamsToContext(ctx, nil, username)
		// TODO: add request logging
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
				return fmt.Errorf("failed to send reply, %v", err)
			}
			return fmt.Errorf("connect to %v failed, %v", request.RawDestAddr, err)
		}
		defer target.Close() // nolint: errcheck

		// Send success
		if err := socks5.SendReply(writer, statute.RepSuccess, target.LocalAddr()); err != nil {
			return fmt.Errorf("failed to send reply, %v", err)
		}

		return forward(ctx, username, wrapSOCKS(request.Reader, writer), target)
	}
}
