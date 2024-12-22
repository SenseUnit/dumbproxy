package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/SenseUnit/dumbproxy/dialer/dto"
	"github.com/hashicorp/go-multierror"
)

var (
	ErrNoSuitableAddress  = errors.New("no suitable address")
	ErrBadIPAddressLength = errors.New("bad IP address length")
	ErrUnknownNetwork     = errors.New("unknown network")
)

type BoundDialer struct {
	defaultDialer Dialer
	defaultHints  string
}

func NewBoundDialer(defaultDialer Dialer, defaultHints string) *BoundDialer {
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
	lAddr := ""
	if h, la, ok := dto.BoundDialerParamsFromContext(ctx); ok {
		if h != nil {
			hints = *h
		}
		lAddr = la
	}

	parsedHints, err := parseHints(hints, lAddr)
	if err != nil {
		return nil, fmt.Errorf("dial failed: %w", err)
	}

	if len(parsedHints) == 0 {
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
	for _, lIP := range parsedHints {
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

func (d *BoundDialer) WantsHostname(ctx context.Context, net, address string) bool {
	switch net {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6", "ip", "ip4", "ip6":
		return false
	default:
		return WantsHostname(ctx, net, address, d.defaultDialer)
	}
}

var _ HostnameWanter = new(BoundDialer)

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

func parseIPList(list string) ([]net.IP, error) {
	res := make([]net.IP, 0)
	for _, elem := range strings.Split(list, ",") {
		elem = strings.TrimSpace(elem)
		if len(elem) == 0 {
			continue
		}
		if parsed := net.ParseIP(elem); parsed == nil {
			return nil, fmt.Errorf("unable to parse IP address %q", elem)
		} else {
			res = append(res, parsed)
		}
	}
	return res, nil
}

func parseHints(hints, lAddr string) ([]net.IP, error) {
	hints = os.Expand(hints, func(key string) string {
		switch key {
		case "lAddr":
			return lAddr
		default:
			return fmt.Sprintf("<bad key:%q>", key)
		}
	})
	res, err := parseIPList(hints)
	if err != nil {
		return nil, fmt.Errorf("unable to parse source IP hints %q: %w", hints, err)
	}
	return res, nil
}

var _ HostnameWanter = new(BoundDialer)
