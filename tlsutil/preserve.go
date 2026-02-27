package tlsutil

import (
	"crypto/tls"
	"errors"
	"net"
)

type preservedKeyKey struct{}

type nonDefaultKeyUsedKey struct{}

func saveConnKey(conn ConnTagger, key [32]byte) {
	conn.SetTag(preservedKeyKey{}, key)
}

func getConnKey(conn ConnTagger) ([32]byte, bool) {
	saved, ok := conn.GetTag(preservedKeyKey{})
	if !ok {
		return [32]byte{}, false
	}
	key, ok := saved.([32]byte)
	if !ok {
		return [32]byte{}, false
	}
	return key, true
}

func setNonDefaultKeyUsed(conn ConnTagger, b bool) {
	conn.SetTag(nonDefaultKeyUsedKey{}, b)
}

func WasNonDefaultKeyUsed(conn net.Conn) bool {
	tagger, ok := conn.(ConnTagger)
	if !ok {
		if netconner, ok := conn.(interface {
			NetConn() net.Conn
		}); ok {
			return WasNonDefaultKeyUsed(netconner.NetConn())
		}
		return false
	}
	saved, ok := tagger.GetTag(nonDefaultKeyUsedKey{})
	if !ok {
		return false
	}
	val, _ := saved.(bool)
	return val
}

func PreserveSessionKeys(cfg *tls.Config, keys [][32]byte) *tls.Config {
	if len(keys) < 2 {
		// there's just one key defined, nothing to do
		return cfg
	}
	forkConfig := func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		return cfg.Clone(), nil
	}
	if cfg.GetConfigForClient != nil {
		forkConfig = cfg.GetConfigForClient
	}
	cfg = cfg.Clone()
	cfg.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		conn, ok := chi.Conn.(ConnTagger)
		if !ok {
			return nil, errors.New("tlsCfg.GetConfigForClient: connection does is not a ConnTagger")
		}
		cfg, err := forkConfig(chi)
		if err != nil {
			return nil, err
		}
		cfg.UnwrapSession = func(identity []byte, cs tls.ConnectionState) (*tls.SessionState, error) {
			skCfg := cfg.Clone()
			skCfg.SessionTicketKey = [32]byte{}
			for ki, key := range keys {
				skCfg.SetSessionTicketKeys([][32]byte{key})
				ss, err := skCfg.DecryptTicket(identity, cs)
				if err != nil {
					return nil, err
				}
				if ss != nil {
					// key match
					saveConnKey(conn, key)
					setNonDefaultKeyUsed(conn, ki > 0)
					return ss, nil
				}
			}
			return nil, nil
		}
		cfg.WrapSession = func(cs tls.ConnectionState, ss *tls.SessionState) ([]byte, error) {
			// is there previous key? if so, use it
			if key, ok := getConnKey(conn); ok {
				skCfg := cfg.Clone()
				skCfg.SessionTicketKey = [32]byte{}
				skCfg.SetSessionTicketKeys([][32]byte{key})
				return skCfg.EncryptTicket(cs, ss)
			}
			return cfg.EncryptTicket(cs, ss)
		}
		return cfg, nil
	}
	return cfg
}
