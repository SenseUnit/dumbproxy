package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
)

func ExpectPeerName(name string, roots *x509.CertPool) func(cs tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		opts := x509.VerifyOptions{
			Roots:         roots,
			DNSName:       name,
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}
		_, err := cs.PeerCertificates[0].Verify(opts)
		return err
	}
}

func LoadCAfile(filename string) (*x509.CertPool, error) {
	roots := x509.NewCertPool()
	pem, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("unable to load CA PEM from file %q: %w", filename, err)
	}
	if ok := roots.AppendCertsFromPEM(pem); !ok {
		return nil, fmt.Errorf("no certificates were read from CA file %q", filename)
	}
	return roots, nil
}

var (
	cipherNameToID map[string]uint16
	curveNameToID  map[string]tls.CurveID
	fullCurveList  = []tls.CurveID{
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
		tls.X25519,
		tls.X25519MLKEM768,
	}
)

func Curves() []tls.CurveID {
	res := make([]tls.CurveID, len(fullCurveList))
	copy(res, fullCurveList)
	return res
}

func init() {
	cipherNameToID = make(map[string]uint16)
	for _, cipher := range tls.CipherSuites() {
		cipherNameToID[cipher.Name] = cipher.ID
	}
	curveNameToID = make(map[string]tls.CurveID)
	for _, curve := range fullCurveList {
		curveNameToID[curve.String()] = curve
	}
}

func ParseCipherList(ciphers string) ([]uint16, error) {
	if ciphers == "" {
		return nil, nil
	}

	cipherNameList := strings.Split(ciphers, ":")
	cipherIDList := make([]uint16, 0, len(cipherNameList))

	for _, name := range cipherNameList {
		id, ok := cipherNameToID[name]
		if !ok {
			return nil, fmt.Errorf("unknown cipher %q", name)
		}
		cipherIDList = append(cipherIDList, id)
	}

	return cipherIDList, nil
}

func ParseCurveList(curves string) ([]tls.CurveID, error) {
	if curves == "" {
		return nil, nil
	}

	curveNameList := strings.Split(curves, ":")
	curveIDList := make([]tls.CurveID, 0, len(curveNameList))

	for _, name := range curveNameList {
		id, ok := curveNameToID[name]
		if !ok {
			return nil, fmt.Errorf("unknown curve %q", name)
		}
		curveIDList = append(curveIDList, id)
	}

	return curveIDList, nil
}

func ParseVersion(s string) (uint16, error) {
	var ver uint16
	switch strings.ToUpper(s) {
	case "TLS10":
		ver = tls.VersionTLS10
	case "TLS11":
		ver = tls.VersionTLS11
	case "TLS12":
		ver = tls.VersionTLS12
	case "TLS13":
		ver = tls.VersionTLS13
	case "TLS1.0":
		ver = tls.VersionTLS10
	case "TLS1.1":
		ver = tls.VersionTLS11
	case "TLS1.2":
		ver = tls.VersionTLS12
	case "TLS1.3":
		ver = tls.VersionTLS13
	case "10":
		ver = tls.VersionTLS10
	case "11":
		ver = tls.VersionTLS11
	case "12":
		ver = tls.VersionTLS12
	case "13":
		ver = tls.VersionTLS13
	case "1.0":
		ver = tls.VersionTLS10
	case "1.1":
		ver = tls.VersionTLS11
	case "1.2":
		ver = tls.VersionTLS12
	case "1.3":
		ver = tls.VersionTLS13
	case "":
	default:
		return 0, fmt.Errorf("unknown TLS version %q", s)
	}
	return ver, nil
}

func FormatVersion(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS10"
	case tls.VersionTLS11:
		return "TLS11"
	case tls.VersionTLS12:
		return "TLS12"
	case tls.VersionTLS13:
		return "TLS13"
	default:
		return fmt.Sprintf("%#04x", v)
	}
}
