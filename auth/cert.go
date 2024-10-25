package auth

import (
	"encoding/hex"
	"fmt"
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
	return string(buf[:len(buf)-1])
}
