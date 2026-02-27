package tlsutil

import (
	"net"
	"sync"
)

type ConnTagger interface {
	GetTag(any) (any, bool)
	SetTag(any, any)
}

type TaggedConn struct {
	net.Conn
	mux  sync.RWMutex
	tags map[any]any
}

func (c *TaggedConn) SetTag(key, value any) {
	c.mux.Lock()
	defer c.mux.Unlock()
	if c.tags == nil {
		c.tags = make(map[any]any)
	}
	c.tags[key] = value
}

func (c *TaggedConn) GetTag(key any) (any, bool) {
	c.mux.RLock()
	defer c.mux.RUnlock()
	value, ok := c.tags[key]
	return value, ok
}

func NewTaggedConn(conn net.Conn) *TaggedConn {
	return &TaggedConn{
		Conn: conn,
	}
}

type TaggedConnListener struct {
	net.Listener
}

func (l TaggedConnListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	_, ok := conn.(ConnTagger)
	if ok {
		return conn, nil
	}
	return NewTaggedConn(conn), nil
}

func NewTaggedConnListener(l net.Listener) TaggedConnListener {
	return TaggedConnListener{
		Listener: l,
	}
}

var _ net.Conn = new(TaggedConn)
var _ net.Listener = TaggedConnListener{}
var _ ConnTagger = new(TaggedConn)
