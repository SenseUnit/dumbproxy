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
)

type CertAuth struct{}

func (_ CertAuth) Validate(wr http.ResponseWriter, req *http.Request) (string, bool) {
	if req.TLS == nil || len(req.TLS.VerifiedChains) < 1 || len(req.TLS.VerifiedChains[0]) < 1 {
		http.Error(wr, BAD_REQ_MSG, http.StatusBadRequest)
		return "", false
	}
	return fmt.Sprintf(
		"Subject: %s, Serial Number: %s",
		req.TLS.VerifiedChains[0][0].Subject.String(),
		formatSerial(req.TLS.VerifiedChains[0][0].SerialNumber),
	), true
}

func (_ CertAuth) Stop() {}

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

type serialNumberKey = [20]byte
type serialNumberSet struct {
	sns map[serialNumberKey]struct{}
}

func normalizeSNBytes(b []byte) serialNumberKey {
	var k serialNumberKey
	copy(
		k[max(len(k)-len(b), 0):],
		b[max(len(b)-len(k), 0):],
	)
	return k
}

func (s *serialNumberSet) Has(serial *big.Int) bool {
	key := normalizeSNBytes(serial.Bytes())
	if s == nil || s.sns == nil {
		return false
	}
	_, found := s.sns[key]
	return found
}

func newSerialNumberSetFromReader(r io.Reader) (*serialNumberSet, error) {
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
			continue
		}
		set[normalizeSNBytes(serial)] = struct{}{}
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
