package tlsutil

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"go.etcd.io/bbolt"

	clog "github.com/SenseUnit/dumbproxy/log"
)

var (
	bucketName               = []byte("tickets")
	currentFormatVersion     = getSessionFormatVer()
	ErrFormatVersionMismatch = errors.New("format version mismatch")
)

func getSessionFormatVer() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	return bi.GoVersion
}

type sessionCacheEntry struct {
	formatVersion string
	ticket        []byte
	state         []byte
}

func uintToVarintBytes(x uint) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, uint64(x))
	return buf[:n]
}

func (e *sessionCacheEntry) MarshalBinary() (data []byte, err error) {
	buf := new(bytes.Buffer)
	_, _ = buf.Write(uintToVarintBytes(uint(len(e.formatVersion))))
	_, _ = buf.WriteString(e.formatVersion)
	_, _ = buf.Write(uintToVarintBytes(uint(len(e.ticket))))
	_, _ = buf.Write(e.ticket)
	_, _ = buf.Write(uintToVarintBytes(uint(len(e.state))))
	_, _ = buf.Write(e.state)
	return append([]byte(nil), buf.Bytes()...), nil
}

func (e *sessionCacheEntry) UnmarshalBinary(data []byte) error {
	r := bytes.NewReader(data)

	formatVerLen, err := binary.ReadUvarint(r)
	if err != nil {
		return fmt.Errorf("unable to read length of format version field: %w", err)
	}
	formatVerBytes := make([]byte, formatVerLen)
	_, err = io.ReadFull(r, formatVerBytes)
	if err != nil {
		return fmt.Errorf("unable to read format version field: %w", err)
	}

	ticketLen, err := binary.ReadUvarint(r)
	if err != nil {
		return fmt.Errorf("unable to read length of ticket field: %w", err)
	}
	ticketBytes := make([]byte, ticketLen)
	_, err = io.ReadFull(r, ticketBytes)
	if err != nil {
		return fmt.Errorf("unable to read ticket field: %w", err)
	}

	stateLen, err := binary.ReadUvarint(r)
	if err != nil {
		return fmt.Errorf("unable to read length of state field: %w", err)
	}
	stateBytes := make([]byte, stateLen)
	_, err = io.ReadFull(r, stateBytes)
	if err != nil {
		return fmt.Errorf("unable to read state field: %w", err)
	}

	e.formatVersion = string(formatVerBytes)
	e.ticket = ticketBytes
	e.state = stateBytes

	return nil
}

func clientSessionStateToBytes(cs *tls.ClientSessionState) ([]byte, error) {
	ticket, state, err := cs.ResumptionState()
	if err != nil {
		return nil, err
	}
	stateBytes, err := state.Bytes()
	if err != nil {
		return nil, err
	}
	return (&sessionCacheEntry{
		formatVersion: currentFormatVersion,
		ticket:        ticket,
		state:         stateBytes,
	}).MarshalBinary()
}

func clientSessionStateFromBytes(data []byte) (*tls.ClientSessionState, error) {
	sce := new(sessionCacheEntry)
	err := sce.UnmarshalBinary(data)
	if err != nil {
		return nil, fmt.Errorf("TLS session state unmarshaling failed: %w", err)
	}
	if sce.formatVersion != currentFormatVersion {
		return nil, ErrFormatVersionMismatch
	}
	ss, err := tls.ParseSessionState(sce.state)
	if err != nil {
		return nil, fmt.Errorf("unable to parse TLS client session state: %w", err)
	}
	cs, err := tls.NewResumptionState(sce.ticket, ss)
	if err != nil {
		return nil, fmt.Errorf("unable to construct new resumption state: %w", err)
	}
	return cs, nil
}

var SessionCache tls.ClientSessionCache = tls.NewLRUClientSessionCache(0)

type PersistentClientSessionCache struct {
	db     *bbolt.DB
	logger *clog.CondLogger
}

func NewPersistentClientSessionCache(path string, logger *clog.CondLogger) (*PersistentClientSessionCache, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	db, err := bbolt.Open(path, 0600, &bbolt.Options{
		Timeout: 5 * time.Second,
		Logger:  bboltLogger{logger},
	})
	if err != nil {
		return nil, err
	}
	return &PersistentClientSessionCache{
		db:     db,
		logger: logger,
	}, nil
}

func (cache *PersistentClientSessionCache) Get(sessionKey string) (*tls.ClientSessionState, bool) {
	var data []byte
	err := cache.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketName)
		if bucket == nil {
			return nil
		}
		data = bucket.Get([]byte(sessionKey))
		return nil
	})
	if err != nil {
		cache.logger.Error("cache db: key %q read failed: %v", err)
		return nil, false
	}
	if data == nil {
		return nil, false
	}
	cs, err := clientSessionStateFromBytes(data)
	if err != nil {
		if err == ErrFormatVersionMismatch {
			cache.logger.Debug("rejected cached ticket for key %q due to version mismatch", sessionKey)
		} else {
			cache.logger.Error("cached session recovery failed: %v", err)
		}
	}
	return cs, true
}

func (cache *PersistentClientSessionCache) delete(sessionKey string) {
	err := cache.db.Update(func(tx *bbolt.Tx) error {
		if bucket := tx.Bucket(bucketName); bucket != nil {
			return bucket.Delete([]byte(sessionKey))
		}
		return nil
	})
	if err != nil {
		cache.logger.Error("cache db: key %q delete failed: %v", sessionKey, err)
	}
}

func (cache *PersistentClientSessionCache) put(sessionKey string, cs *tls.ClientSessionState) {
	csBytes, err := clientSessionStateToBytes(cs)
	if err != nil {
		cache.logger.Error("dropping client session state with key %q: unable to marshal client session state: %v", sessionKey, err)
		return
	}
	err = cache.db.Update(func(tx *bbolt.Tx) error {
		if bucket, err := tx.CreateBucketIfNotExists(bucketName); err == nil {
			return bucket.Put([]byte(sessionKey), csBytes)
		} else {
			return err
		}
	})
	if err != nil {
		cache.logger.Error("cache db: key %q write failed: %v", sessionKey, err)
	}
}

func (cache *PersistentClientSessionCache) Put(sessionKey string, cs *tls.ClientSessionState) {
	if cs == nil {
		cache.delete(sessionKey)
		return
	} else {
		cache.put(sessionKey, cs)
	}
}

type bboltLogger struct {
	l *clog.CondLogger
}

func (l bboltLogger) Debug(v ...any) {
	l.l.Debug("%s", fmt.Sprint(v...))
}

func (l bboltLogger) Debugf(format string, v ...any) {
	l.l.Debug(format, v...)
}

func (l bboltLogger) Error(v ...any) {
	l.l.Error("%s", fmt.Sprint(v...))
}

func (l bboltLogger) Errorf(format string, v ...any) {
	l.l.Error(format, v...)
}

func (l bboltLogger) Info(v ...any) {
	l.l.Info("%s", fmt.Sprint(v...))
}

func (l bboltLogger) Infof(format string, v ...any) {
	l.l.Info(format, v...)
}

func (l bboltLogger) Warning(v ...any) {
	l.l.Warning("%s", fmt.Sprint(v...))
}

func (l bboltLogger) Warningf(format string, v ...any) {
	l.l.Warning(format, v...)
}

func (l bboltLogger) Fatal(v ...any) {
	l.l.Critical("%s", fmt.Sprint(v...))
	os.Exit(1)
}

func (l bboltLogger) Fatalf(format string, v ...any) {
	l.l.Critical(format, v...)
	os.Exit(1)
}

func (l bboltLogger) Panic(v ...any) {
	s := fmt.Sprint(v...)
	l.l.Critical("%s", s)
	panic(s)
}

func (l bboltLogger) Panicf(format string, v ...any) {
	s := fmt.Sprintf(format, v...)
	l.l.Critical("%s", s)
	panic(s)
}
