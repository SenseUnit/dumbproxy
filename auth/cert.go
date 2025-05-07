package auth

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	clog "github.com/SenseUnit/dumbproxy/log"

	us "github.com/Snawoot/uniqueslice"
)

type serialNumberSetFile struct {
	file    *serialNumberSet
	modTime time.Time
}

type CertAuth struct {
	blacklist         atomic.Pointer[serialNumberSetFile]
	blacklistFilename string
	logger            *clog.CondLogger
	stopOnce          sync.Once
	stopChan          chan struct{}
}

func NewCertAuth(param_url *url.URL, logger *clog.CondLogger) (*CertAuth, error) {
	values, err := url.ParseQuery(param_url.RawQuery)
	if err != nil {
		return nil, err
	}

	auth := &CertAuth{
		blacklistFilename: values.Get("blacklist"),
		logger:            logger,
		stopChan:          make(chan struct{}),
	}
	auth.blacklist.Store(new(serialNumberSetFile))

	reloadInterval := 15 * time.Second
	if reloadIntervalOption := values.Get("reload"); reloadIntervalOption != "" {
		parsedInterval, err := time.ParseDuration(reloadIntervalOption)
		if err != nil {
			logger.Warning("unable to parse reload interval: %v. using default value.", err)
		}
		reloadInterval = parsedInterval
	}
	if auth.blacklistFilename != "" {
		if err := auth.reload(); err != nil {
			return nil, fmt.Errorf("unable to load initial certificate blacklist: %w", err)
		}
		if reloadInterval > 0 {
			go auth.reloadLoop(reloadInterval)
		}
	}

	return auth, nil
}

func (auth *CertAuth) Validate(wr http.ResponseWriter, req *http.Request) (string, bool) {
	if req.TLS == nil || len(req.TLS.VerifiedChains) < 1 || len(req.TLS.VerifiedChains[0]) < 1 {
		http.Error(wr, BAD_REQ_MSG, http.StatusBadRequest)
		return "", false
	}
	eeCert := req.TLS.VerifiedChains[0][0]
	if auth.blacklist.Load().file.Has(eeCert.SerialNumber) {
		http.Error(wr, BAD_REQ_MSG, http.StatusBadRequest)
		return "", false
	}
	return fmt.Sprintf(
		"Subject: %s, Serial Number: %s",
		eeCert.Subject.String(),
		formatSerial(eeCert.SerialNumber),
	), true
}

func (auth *CertAuth) Stop() {
	auth.stopOnce.Do(func() {
		close(auth.stopChan)
	})
}

func (auth *CertAuth) reload() error {
	var oldModTime time.Time
	if oldBL := auth.blacklist.Load(); oldBL != nil {
		oldModTime = oldBL.modTime
	}

	f, modTime, err := openIfModified(auth.blacklistFilename, oldModTime)
	if err != nil {
		return err
	}
	if f == nil {
		// no changes since last modTime
		return nil
	}

	auth.logger.Info("reloading certificate blacklist from %q...", auth.blacklistFilename)
	newBlacklistSet, err := newSerialNumberSetFromReader(f, func(parseErr error) {
		auth.logger.Error("failed to parse line in %q: %v", auth.blacklistFilename, parseErr)
	})
	if err != nil {
		return err
	}

	newBlacklist := &serialNumberSetFile{
		file:    newBlacklistSet,
		modTime: modTime,
	}
	auth.blacklist.Store(newBlacklist)
	auth.logger.Info("blacklist file reloaded.")

	return nil
}

func (auth *CertAuth) reloadLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-auth.stopChan:
			return
		case <-ticker.C:
			if err := auth.reload(); err != nil {
				auth.logger.Error("reload failed: %v", err)
			}
		}
	}
}

// formatSerial from https://codereview.stackexchange.com/a/165708
func formatSerial(serial *big.Int) string {
	b := serial.Bytes()
	buf := make([]byte, 0, 3*len(b))
	x := buf[1*len(b) : 3*len(b)]
	hex.Encode(x, b)
	for i := 0; i < len(x); i += 2 {
		buf = append(buf, x[i], x[i+1], ':')
	}
	if serial.Sign() == -1 {
		return "(Negative)" + string(buf[:len(buf)-1])
	}
	return string(buf[:len(buf)-1])
}

type serialNumberKey = us.Handle[[]byte, byte]
type serialNumberSet struct {
	sns map[serialNumberKey]struct{}
}

func cutLeadingZeroes(b []byte) []byte {
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	return b
}

func (s *serialNumberSet) Has(serial *big.Int) bool {
	key := us.Make(cutLeadingZeroes(serial.Bytes()))
	if s == nil || s.sns == nil {
		return false
	}
	_, found := s.sns[key]
	return found
}

func newSerialNumberSetFromReader(r io.Reader, bad func(error)) (*serialNumberSet, error) {
	set := make(map[serialNumberKey]struct{})
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line, _, _ := bytes.Cut(scanner.Bytes(), []byte{'#'})
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		serial, err := parseSerialBytes(line)
		if err != nil {
			if bad != nil {
				bad(fmt.Errorf("bad serial number line %q: %w", line, err))
			}
			continue
		}
		set[us.Make(cutLeadingZeroes(serial))] = struct{}{}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("unable to load serial number set: %w", err)
	}

	return &serialNumberSet{
		sns: set,
	}, nil
}

func parseSerialBytes(serial []byte) ([]byte, error) {
	res := make([]byte, (len(serial)+2)/3)

	var i int
	for ; i < len(res) && i*3+1 < len(serial); i++ {
		if _, err := hex.Decode(res[i:i+1], serial[i*3:i*3+2]); err != nil {
			return nil, fmt.Errorf("parseSerialBytes() failed: %w", err)
		}
		if i*3+2 < len(serial) && serial[i*3+2] != ':' {
			return nil, errors.New("missing colon delimiter")
		}
	}
	if i < len(res) {
		return nil, errors.New("incomplete serial number string")
	}

	return res, nil
}
