package handler

import (
	"net"
)

func StreamServe(l net.Listener, h func(conn net.Conn)) error {
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go h(conn)
	}
}
