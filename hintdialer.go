package main

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/hashicorp/go-multierror"
)

var (
	ErrNoSuitableAddress  = errors.New("no suitable address")
	ErrBadIPAddressLength = errors.New("bad IP address length")
	ErrUnknownNetwork     = errors.New("unknown network")
)

type BoundDialerContextKey struct{}

type BoundDialerDefaultSink interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type BoundDialer struct {
	defaultDialer BoundDialerDefaultSink
	defaultHints  []net.IP
}

func NewBoundDialer(defaultDialer BoundDialerDefaultSink, defaultHints []net.IP) *BoundDialer {
	if defaultDialer == nil {
		defaultDialer = &net.Dialer{}
	}
	return &BoundDialer{
		defaultDialer: defaultDialer,
		defaultHints:  defaultHints,
	}
}

func (d *BoundDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	hints := d.defaultHints
	if hintsOverride := ctx.Value(BoundDialerContextKey{}); hintsOverride != nil {
		if hintsOverrideValue, ok := hintsOverride.([]net.IP); ok {
			hints = hintsOverrideValue
		}
	}

	if len(hints) == 0 {
		return d.defaultDialer.DialContext(ctx, network, address)
	}

	var netBase string
	switch network {
	case "tcp", "tcp4", "tcp6":
		netBase = "tcp"
	case "udp", "udp4", "udp6":
		netBase = "udp"
	case "ip", "ip4", "ip6":
		netBase = "ip"
	default:
		return d.defaultDialer.DialContext(ctx, network, address)
	}

	var resErr error
	for _, lIP := range hints {
		lAddr, restrictedNetwork, err := ipToLAddr(netBase, lIP)
		if err != nil {
			resErr = multierror.Append(resErr, fmt.Errorf("ipToLAddr(%q) failed: %w", lIP.String(), err))
			continue
		}
		if network != netBase && network != restrictedNetwork {
			continue
		}

		conn, err := (&net.Dialer{
			LocalAddr: lAddr,
		}).DialContext(ctx, restrictedNetwork, address)
		if err != nil {
			resErr = multierror.Append(resErr, fmt.Errorf("dial failed: %w", err))
		} else {
			return conn, nil
		}
	}

	if resErr == nil {
		resErr = ErrNoSuitableAddress
	}
	return nil, resErr
}

func (d *BoundDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func ipToLAddr(network string, ip net.IP) (net.Addr, string, error) {
	v6 := true
	if ip4 := ip.To4(); len(ip4) == net.IPv4len {
		ip = ip4
		v6 = false
	} else if len(ip) != net.IPv6len {
		return nil, "", ErrBadIPAddressLength
	}

	var lAddr net.Addr
	var lNetwork string
	switch network {
	case "tcp", "tcp4", "tcp6":
		lAddr = &net.TCPAddr{
			IP: ip,
		}
		if v6 {
			lNetwork = "tcp6"
		} else {
			lNetwork = "tcp4"
		}
	case "udp", "udp4", "udp6":
		lAddr = &net.UDPAddr{
			IP: ip,
		}
		if v6 {
			lNetwork = "udp6"
		} else {
			lNetwork = "udp4"
		}
	case "ip", "ip4", "ip6":
		lAddr = &net.IPAddr{
			IP: ip,
		}
		if v6 {
			lNetwork = "ip6"
		} else {
			lNetwork = "ip4"
		}
	default:
		return nil, "", ErrUnknownNetwork
	}

	return lAddr, lNetwork, nil
}
