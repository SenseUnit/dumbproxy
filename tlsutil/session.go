package tlsutil

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"errors"
	"net"

	clog "github.com/SenseUnit/dumbproxy/log"
)

const tlsCookiePrefix = "dpSessionCookieV1="

type TLSSessionID = [16]byte

func NewTLSSessionID() (res TLSSessionID) {
	crand.Read(res[:])
	return
}

func TLSSessionIDFromState(ss *tls.SessionState) (TLSSessionID, bool) {
	for _, tag := range ss.Extra {
		if !bytes.HasPrefix(tag, []byte(tlsCookiePrefix)) {
			continue
		}
		tag = tag[len(tlsCookiePrefix):]
		if len(tag) != len(TLSSessionID{}) {
			continue
		}
		return TLSSessionID(tag), true
	}
	return TLSSessionID{}, false
}

type tlsSessionIDKey struct{}
type connKey struct{}

func getTLSSessionID(conn ConnTagger) (TLSSessionID, bool) {
	saved, ok := conn.GetTag(tlsSessionIDKey{})
	if !ok {
		return TLSSessionID{}, false
	}
	val, ok := saved.(TLSSessionID)
	return val, ok
}

func setTLSSessionID(conn ConnTagger, sessionID TLSSessionID) {
	conn.SetTag(tlsSessionIDKey{}, sessionID)
}

func GetTLSSessionID(conn net.Conn) (TLSSessionID, bool) {
	tagger, ok := conn.(ConnTagger)
	if !ok {
		if netconner, ok := conn.(interface {
			NetConn() net.Conn
		}); ok {
			return GetTLSSessionID(netconner.NetConn())
		}
		return TLSSessionID{}, false
	}
	return getTLSSessionID(tagger)
}

func ConnToContext(ctx context.Context, conn net.Conn) context.Context {
	return context.WithValue(ctx, connKey{}, conn)
}

func ConnFromContext(ctx context.Context) (net.Conn, bool) {
	val := ctx.Value(connKey{})
	conn, ok := val.(net.Conn)
	return conn, ok
}

func EnableTLSCookies(cfg *tls.Config, logger *clog.CondLogger) *tls.Config {
	getConfig := func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		return cfg.Clone(), nil
	}
	if cfg.GetConfigForClient != nil {
		getConfig = cfg.GetConfigForClient
	}
	// this one will be returned as updated TLS config to outer function caller
	cfg = cfg.Clone()
	cfg.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		conn, ok := chi.Conn.(ConnTagger)
		remoteAddr := chi.Conn.RemoteAddr().String()
		if !ok {
			return nil, errors.New("tlsCfg.GetConfigForClient: connection does is not a ConnTagger")
		}
		// this one holds closures which capture conn
		cfg, err := getConfig(chi)
		if err != nil {
			return nil, err
		}
		cfg.UnwrapSession = func(identity []byte, cs tls.ConnectionState) (*tls.SessionState, error) {
			ss, err := cfg.DecryptTicket(identity, cs)
			if err != nil {
				logger.Error("got error from TLS session ticket decryption: %v", err)
				return nil, err
			}
			if ss == nil {
				// nothing was decrypted, issue a new session
				sessionID := NewTLSSessionID()
				logger.Debug("assigning NEW session ID %x to connection from %s", sessionID, remoteAddr)
				setTLSSessionID(conn, sessionID)
				return nil, nil
			}
			if sessionID, ok := TLSSessionIDFromState(ss); ok {
				// valid session ID in ticket
				logger.Debug("recovered session ID = %x from %s", sessionID, remoteAddr)
				setTLSSessionID(conn, sessionID)
			} else {
				// no valid session ID in ticket (migrating outdated ticket?)
				sessionID = NewTLSSessionID()
				logger.Debug("session ID was NOT recovered from ticket from %s. assigning NEW session ID %x", remoteAddr, sessionID)
				setTLSSessionID(conn, sessionID)
			}
			return ss, nil
		}
		cfg.WrapSession = func(cs tls.ConnectionState, ss *tls.SessionState) ([]byte, error) {
			// is there session in TLS session state already?
			if sessionID, found := TLSSessionIDFromState(ss); found {
				logger.Warning("sessionState from %s already has sessionID %x", remoteAddr, sessionID)
				setTLSSessionID(conn, sessionID)
				return cfg.EncryptTicket(cs, ss)
			}
			// did we had a chance to assign a session ID to this connection?
			sessionID, ok := getTLSSessionID(conn)
			if ok {
				logger.Debug("sending new TLS ticket with old session ID %x to remote %s", sessionID, remoteAddr)
			} else {
				sessionID = NewTLSSessionID()
				setTLSSessionID(conn, sessionID)
				logger.Debug("sending new TLS ticket with NEW session ID %x to remote %s", sessionID, remoteAddr)
			}
			cookie := append([]byte(tlsCookiePrefix), sessionID[:]...)
			ss.Extra = append(ss.Extra, cookie)
			return cfg.EncryptTicket(cs, ss)
		}
		return cfg, nil
	}
	return cfg
}
