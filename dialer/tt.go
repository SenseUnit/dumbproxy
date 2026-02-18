package dialer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Snawoot/secache"
	"github.com/Snawoot/secache/randmap"
	xproxy "golang.org/x/net/proxy"

	clog "github.com/SenseUnit/dumbproxy/log"
)

const UDPSessionLifetime = 120 * time.Second

type ClientOriginatedPacket struct {
	Src netip.AddrPort
	Dst netip.AddrPort
	App string
	Dat []byte
}

func (p *ClientOriginatedPacket) UnmarshalBinary(data []byte) error {
	l := len(data)
	if l < 41 {
		return fmt.Errorf("binary representation of client-originated packet is too short: %d byte(s)", len(data))
	}
	totalSize := binary.BigEndian.Uint32(data) + 4
	if int64(totalSize) != int64(l) {
		return fmt.Errorf("packet with incorrect length came from demuxer: %d byte(s) packet with %d byte(s) length in header", l, totalSize)
	}
	data = data[4:]

	srcBytes := data[:16]
	data = data[16:]

	srcPort := binary.BigEndian.Uint16(data)
	data = data[2:]

	dstBytes := data[:16]
	data = data[16:]

	dstPort := binary.BigEndian.Uint16(data)
	data = data[2:]

	appNameLen := data[0]
	data = data[1:]

	if int(appNameLen) > len(data) {
		return fmt.Errorf("app name data len doesn't fit designated packet length: %d byte(s) in %d byte(s) packet", appNameLen, totalSize)
	}

	appName := string(data[:appNameLen])
	data = data[appNameLen:]

	var srcA, dstA netip.Addr
	var ok bool
	if slices.Min(srcBytes[:12]) == 0 && slices.Min(dstBytes[:12]) == 0 {
		srcA, ok = netip.AddrFromSlice(srcBytes[12:])
		if !ok {
			panic("check extracted address length")
		}
		dstA, ok = netip.AddrFromSlice(dstBytes[12:])
		if !ok {
			panic("check extracted address length")
		}
	} else {
		srcA, ok = netip.AddrFromSlice(srcBytes)
		if !ok {
			panic("check extracted address length")
		}
		dstA, ok = netip.AddrFromSlice(dstBytes)
		if !ok {
			panic("check extracted address length")
		}
	}
	srcEP := netip.AddrPortFrom(srcA, srcPort)
	dstEP := netip.AddrPortFrom(dstA, dstPort)

	p.Src = srcEP
	p.Dst = dstEP
	p.App = appName
	p.Dat = data
	return nil
}

type ServerOriginatedPacket struct {
	Src netip.AddrPort
	Dst netip.AddrPort
	Dat []byte
}

func (p *ServerOriginatedPacket) MarshalBinary() (data []byte, err error) {
	l := uint32(16 + 2 + 16 + 2 + len(p.Dat))
	buf := bytes.NewBuffer(make([]byte, 0, l))
	srcAddr := p.Src.Addr().Unmap()
	dstAddr := p.Dst.Addr().Unmap()
	binary.Write(buf, binary.BigEndian, l)
	if srcAddr.Is4() && dstAddr.Is4() {
		binary.Write(buf, binary.BigEndian, [12]byte{})
		binary.Write(buf, binary.BigEndian, srcAddr.As4())
		binary.Write(buf, binary.BigEndian, p.Src.Port())
		binary.Write(buf, binary.BigEndian, [12]byte{})
		binary.Write(buf, binary.BigEndian, dstAddr.As4())
		binary.Write(buf, binary.BigEndian, p.Dst.Port())
	} else {
		binary.Write(buf, binary.BigEndian, srcAddr.As16())
		binary.Write(buf, binary.BigEndian, p.Src.Port())
		binary.Write(buf, binary.BigEndian, dstAddr.As16())
		binary.Write(buf, binary.BigEndian, p.Dst.Port())
	}
	buf.Write(p.Dat)
	return buf.Bytes(), nil
}

type dummyAddr struct {
	network string
	address string
}

func (a dummyAddr) Network() string {
	return a.network
}

func (a dummyAddr) String() string {
	return a.address
}

type nullConn struct{}

func (_ nullConn) Read(b []byte) (n int, err error) {
	return 0, io.EOF
}

func (_ nullConn) Write(b []byte) (n int, err error) {
	return 0, net.ErrClosed
}

func (_ nullConn) Close() error {
	return nil
}

func (_ nullConn) LocalAddr() net.Addr {
	return dummyAddr{
		network: "dummy",
		address: "<dummy local address>",
	}
}

func (_ nullConn) RemoteAddr() net.Addr {
	return dummyAddr{
		network: "dummy",
		address: "<dummy remote address>",
	}
}

func (_ nullConn) SetDeadline(t time.Time) error {
	return nil
}

func (_ nullConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (_ nullConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type udpReplyCallback = func(msg []byte, from netip.AddrPort)

type udpPort struct {
	lastUsed atomic.Int64
	conn     net.PacketConn
	cb       udpReplyCallback
}

func newUDPPort(ctx context.Context, cb udpReplyCallback) (*udpPort, error) {
	conn, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", ":0")
	if err != nil {
		return nil, err
	}
	p := new(udpPort)
	p.lastUsed.Store(time.Now().UnixNano())
	p.conn = conn
	p.cb = cb
	go p.recvReplies()
	return p, nil
}

func (p *udpPort) valid() bool {
	if p == nil {
		return false
	}
	v := time.Now().Before(time.Unix(0, p.lastUsed.Load()).Add(UDPSessionLifetime))
	if !v {
		p.close()
	}
	return v
}

func (p *udpPort) recvReplies() {
	buf := make([]byte, 65536)
	for {
		n, addr, err := p.conn.ReadFrom(buf)
		if n > 0 {
			switch a := addr.(type) {
			case *net.UDPAddr:
				p.cb(append([]byte(nil), buf[:n]...), a.AddrPort())
			default:
				p.cb(append([]byte(nil), buf[:n]...), netip.MustParseAddrPort(a.String()))
			}
		}
		p.lastUsed.Store(time.Now().UnixNano())
		if err != nil {
			if te, ok := err.(interface{ Temporary() bool }); ok && te.Temporary() {
				continue
			}
			p.close()
			return
		}
	}
}

func (p *udpPort) send(what []byte, to netip.AddrPort) error {
	p.lastUsed.Store(time.Now().UnixNano())
	_, err := p.conn.WriteTo(what, net.UDPAddrFromAddrPort(to))
	return err
}

func (p *udpPort) close() error {
	p.lastUsed.Store(0)
	return p.conn.Close()
}

type udpDemuxConn struct {
	ctx       context.Context
	cl        func()
	wbuf      bytes.Buffer
	werr      error
	rpipe     *io.PipeReader
	wpipe     *io.PipeWriter
	closeOnce sync.Once
	logger    *clog.CondLogger
	ports     *secache.Cache[netip.AddrPort, *udpPort]
}

func newUDPDemuxConn(ctx context.Context, logger *clog.CondLogger) *udpDemuxConn {
	ctx, cl := context.WithCancel(ctx)
	rpipe, wpipe := io.Pipe()
	return &udpDemuxConn{
		ctx:    ctx,
		cl:     cl,
		logger: logger,
		rpipe:  rpipe,
		wpipe:  wpipe,
		ports: secache.New[netip.AddrPort, *udpPort](
			3,
			func(_ netip.AddrPort, p *udpPort) bool {
				return p.valid()
			},
		),
	}
}

func (m *udpDemuxConn) Read(b []byte) (n int, err error) {
	return m.rpipe.Read(b)
}

func (m *udpDemuxConn) Write(b []byte) (n int, err error) {
	m.logger.Debug("got mux write: %v", b)
	if m.werr != nil {
		return 0, m.werr
	}
	n, err = m.wbuf.Write(b)
	if err1 := m.dispatchIncomingBuffer(); err1 != nil {
		m.werr = fmt.Errorf("udp demux failed: %w", err1)
		return n, m.werr
	}
	return
}

func (m *udpDemuxConn) dispatchIncomingBuffer() error {
	for {
		b := m.wbuf.Bytes()
		l := len(b)
		if l < 4 {
			return nil
		}
		size := binary.BigEndian.Uint32(b)
		if size < 37 || size > 37+65535 {
			return fmt.Errorf("bad UDP encap frame length: %d", size)
		}
		if int64(l) < int64(size)+4 {
			return nil
		}
		cPkt := new(ClientOriginatedPacket)
		if err := cPkt.UnmarshalBinary(b[:size+4]); err != nil {
			m.logger.Error("demux failed: %v", err)
			return err
		}
		if err := m.dispatchIncomingPacket(cPkt); err != nil {
			m.logger.Error("packet <%s => %s> dispatch failed: %v", cPkt.Src.String(), cPkt.Dst.String(), err)
		}
		// TODO: find some simpler way to advance buffer read position
		io.CopyN(io.Discard, &m.wbuf, int64(size+4))
	}
}

func (m *udpDemuxConn) dispatchIncomingPacket(pkt *ClientOriginatedPacket) error {
	var err error
	port := m.ports.GetOrCreate(pkt.Src, func() *udpPort {
		// handle shutdown situation
		if m.werr != nil {
			err = m.werr
			return nil
		}
		var p *udpPort
		p, err = newUDPPort(
			m.ctx,
			func(msg []byte, from netip.AddrPort) {
				err := m.sendReply(pkt.Src, from, msg)
				if err != nil {
					m.logger.Error("unable to send reply datagram: %v", err)
				}
			},
		)
		return p
	})
	if err != nil {
		return err
	}
	err = port.send(pkt.Dat, pkt.Dst)
	m.logger.Debug("sent UDP packet from client %s to server %s err = %v", pkt.Src.String(), pkt.Dst.String(), err)
	return err
}

func (m *udpDemuxConn) sendReply(to, from netip.AddrPort, msg []byte) error {
	replyPacket := &ServerOriginatedPacket{
		Src: from,
		Dst: to,
		Dat: msg,
	}
	encoded, err := replyPacket.MarshalBinary()
	m.logger.Debug("sent UDP reply from %s to %s err = %v", from.String(), to.String(), err)
	if err != nil {
		return err
	}

	_, err = m.wpipe.Write(encoded)
	return err
}

func (m *udpDemuxConn) Close() error {
	m.closeOnce.Do(func() {
		m.werr = net.ErrClosed
		m.cl()
		m.wpipe.Close()
		m.ports.Do(func(m *randmap.RandMap[netip.AddrPort, *udpPort]) {
			for _, port := range m.Range {
				port.close()
			}
		})
	})
	return nil
}

func (_ *udpDemuxConn) LocalAddr() net.Addr {
	return dummyAddr{
		network: "demux",
		address: "<dummy local address>",
	}
}

func (_ *udpDemuxConn) RemoteAddr() net.Addr {
	return dummyAddr{
		network: "demux",
		address: "<dummy remote address>",
	}
}

func (_ *udpDemuxConn) SetDeadline(t time.Time) error {
	return nil
}

func (_ *udpDemuxConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (_ *udpDemuxConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type icmpDemuxConn struct {
}

func newICMPDemuxConn(ctx context.Context, logger *clog.CondLogger) (*icmpDemuxConn, error) {
	return nil, errors.New("not implemented")
}

func (m *icmpDemuxConn) Read(b []byte) (n int, err error) {
	// TODO: implement Read
	return 0, net.ErrClosed
}

func (m *icmpDemuxConn) Write(b []byte) (n int, err error) {
	// TODO: implement Write
	return 0, net.ErrClosed
}

func (m *icmpDemuxConn) Close() error {
	// TODO: implement Close
	return nil
}
func (m *icmpDemuxConn) LocalAddr() net.Addr {
	return dummyAddr{
		network: "demux",
		address: "<dummy local address>",
	}
}

func (m *icmpDemuxConn) RemoteAddr() net.Addr {
	return dummyAddr{
		network: "demux",
		address: "<dummy local address>",
	}
}

func (_ *icmpDemuxConn) SetDeadline(t time.Time) error {
	return nil
}

func (_ *icmpDemuxConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (_ *icmpDemuxConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type TTInterceptor struct {
	next   Dialer
	logger *clog.CondLogger
}

func NewTTInterceptor(next xproxy.Dialer, logger *clog.CondLogger) Dialer {
	return &TTInterceptor{
		next:   MaybeWrapWithContextDialer(next),
		logger: logger,
	}
}

func (d *TTInterceptor) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *TTInterceptor) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch address {
	case "_check":
		return nullConn{}, nil
	case "_udp2":
		return newUDPDemuxConn(ctx, d.logger), nil
	case "_icmp":
		return newICMPDemuxConn(ctx, d.logger)
	default:
		return d.next.DialContext(ctx, network, address)
	}
}

func (d *TTInterceptor) WantsHostname(ctx context.Context, network, address string) bool {
	switch address {
	case "_check", "_udp2", "_icmp":
		return false
	default:
		return WantsHostname(ctx, network, address, d.next)
	}
}

var _ Dialer = new(TTInterceptor)
var _ HostnameWanter = new(TTInterceptor)
