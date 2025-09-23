package resolver

import (
	"context"
	"net"
)

func NewPlainResolver(addr string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{
				Resolver: &net.Resolver{},
			}).DialContext(ctx, network, addr)
		},
	}
}

func NewTCPResolver(addr string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dnet := "tcp"
			switch network {
			case "udp4":
				dnet = "tcp4"
			case "udp6":
				dnet = "tcp6"
			}
			return (&net.Dialer{
				Resolver: &net.Resolver{},
			}).DialContext(ctx, dnet, addr)
		},
	}
}
