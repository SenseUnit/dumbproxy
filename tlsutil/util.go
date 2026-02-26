package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	utls "github.com/refraction-networking/utls"
)

var sessionCache = tls.NewLRUClientSessionCache(0)

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

func TLSConfigFromURL(u *url.URL) (*tls.Config, error) {
	host := u.Hostname()
	params, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("unable to parse query string of proxy specification URL %q: %w", u.String(), err)
	}
	tlsConfig := &tls.Config{
		ServerName:         host,
		ClientSessionCache: sessionCache,
	}
	if params.Has("cafile") {
		roots, err := LoadCAfile(params.Get("cafile"))
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = roots
	}
	if params.Has("sni") {
		tlsConfig.ServerName = params.Get("sni")
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyConnection = ExpectPeerName(host, tlsConfig.RootCAs)
	}
	if params.Has("peername") {
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyConnection = ExpectPeerName(params.Get("peername"), tlsConfig.RootCAs)
	}
	if params.Has("cert") {
		cert, err := tls.LoadX509KeyPair(params.Get("cert"), params.Get("key"))
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	if params.Has("ciphers") {
		cipherList, err := ParseCipherList(params.Get("ciphers"))
		if err != nil {
			return nil, err
		}
		tlsConfig.CipherSuites = cipherList
	}
	if params.Has("curves") {
		curveList, err := ParseCurveList(params.Get("curves"))
		if err != nil {
			return nil, err
		}
		tlsConfig.CurvePreferences = curveList
	}
	if params.Has("min-tls-version") {
		ver, err := ParseVersion(params.Get("min-tls-version"))
		if err != nil {
			return nil, err
		}
		tlsConfig.MinVersion = ver
	}
	if params.Has("max-tls-version") {
		ver, err := ParseVersion(params.Get("max-tls-version"))
		if err != nil {
			return nil, err
		}
		tlsConfig.MaxVersion = ver
	}
	return tlsConfig, nil
}

func TLSFactoryFromURL(u *url.URL) (func(c net.Conn, config *tls.Config) net.Conn, error) {
	params, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("unable to parse query string of proxy specification URL %q: %w", u.String(), err)
	}
	if params.Has("utls-fp") {
		var fp utls.ClientHelloID
		switch params.Get("utls-fp") {
		case "Hello360_11_0":
			fp = utls.Hello360_11_0
		case "Hello360_7_5":
			fp = utls.Hello360_7_5
		case "Hello360_Auto":
			fp = utls.Hello360_Auto
		case "HelloAndroid_11_OkHttp":
			fp = utls.HelloAndroid_11_OkHttp
		case "HelloChrome_100":
			fp = utls.HelloChrome_100
		case "HelloChrome_100_PSK":
			fp = utls.HelloChrome_100_PSK
		case "HelloChrome_102":
			fp = utls.HelloChrome_102
		case "HelloChrome_106_Shuffle":
			fp = utls.HelloChrome_106_Shuffle
		case "HelloChrome_112_PSK_Shuf":
			fp = utls.HelloChrome_112_PSK_Shuf
		case "HelloChrome_114_Padding_PSK_Shuf":
			fp = utls.HelloChrome_114_Padding_PSK_Shuf
		case "HelloChrome_115_PQ":
			fp = utls.HelloChrome_115_PQ
		case "HelloChrome_115_PQ_PSK":
			fp = utls.HelloChrome_115_PQ_PSK
		case "HelloChrome_120":
			fp = utls.HelloChrome_120
		case "HelloChrome_120_PQ":
			fp = utls.HelloChrome_120_PQ
		case "HelloChrome_131":
			fp = utls.HelloChrome_131
		case "HelloChrome_133":
			fp = utls.HelloChrome_133
		case "HelloChrome_58":
			fp = utls.HelloChrome_58
		case "HelloChrome_62":
			fp = utls.HelloChrome_62
		case "HelloChrome_70":
			fp = utls.HelloChrome_70
		case "HelloChrome_72":
			fp = utls.HelloChrome_72
		case "HelloChrome_83":
			fp = utls.HelloChrome_83
		case "HelloChrome_87":
			fp = utls.HelloChrome_87
		case "HelloChrome_96":
			fp = utls.HelloChrome_96
		case "HelloChrome_Auto":
			fp = utls.HelloChrome_Auto
		case "HelloCustom":
			fp = utls.HelloCustom
		case "HelloEdge_106":
			fp = utls.HelloEdge_106
		case "HelloEdge_85":
			fp = utls.HelloEdge_85
		case "HelloEdge_Auto":
			fp = utls.HelloEdge_Auto
		case "HelloFirefox_102":
			fp = utls.HelloFirefox_102
		case "HelloFirefox_105":
			fp = utls.HelloFirefox_105
		case "HelloFirefox_120":
			fp = utls.HelloFirefox_120
		case "HelloFirefox_55":
			fp = utls.HelloFirefox_55
		case "HelloFirefox_56":
			fp = utls.HelloFirefox_56
		case "HelloFirefox_63":
			fp = utls.HelloFirefox_63
		case "HelloFirefox_65":
			fp = utls.HelloFirefox_65
		case "HelloFirefox_99":
			fp = utls.HelloFirefox_99
		case "HelloFirefox_Auto":
			fp = utls.HelloFirefox_Auto
		case "HelloGolang":
			fp = utls.HelloGolang
		case "HelloIOS_11_1":
			fp = utls.HelloIOS_11_1
		case "HelloIOS_12_1":
			fp = utls.HelloIOS_12_1
		case "HelloIOS_13":
			fp = utls.HelloIOS_13
		case "HelloIOS_14":
			fp = utls.HelloIOS_14
		case "HelloIOS_Auto":
			fp = utls.HelloIOS_Auto
		case "HelloQQ_11_1":
			fp = utls.HelloQQ_11_1
		case "HelloQQ_Auto":
			fp = utls.HelloQQ_Auto
		case "HelloRandomized":
			fp = utls.HelloRandomized
		case "HelloRandomizedALPN":
			fp = utls.HelloRandomizedALPN
		case "HelloRandomizedNoALPN":
			fp = utls.HelloRandomizedNoALPN
		case "HelloSafari_16_0":
			fp = utls.HelloSafari_16_0
		case "HelloSafari_Auto":
			fp = utls.HelloSafari_Auto
		default:
			return nil, fmt.Errorf("unknown uTLS client hello ID %q", params.Get("utls-fp"))
		}
		return func(c net.Conn, config *tls.Config) net.Conn {
			var ucfg *utls.Config
			if config != nil {
				ucfg = &utls.Config{
					Rand:                        config.Rand,
					Time:                        config.Time,
					Certificates:                castCertsToUCerts(config.Certificates),
					RootCAs:                     config.RootCAs,
					NextProtos:                  config.NextProtos,
					ServerName:                  config.ServerName,
					ClientAuth:                  utls.ClientAuthType(config.ClientAuth),
					ClientCAs:                   config.ClientCAs,
					InsecureSkipVerify:          config.InsecureSkipVerify,
					CipherSuites:                config.CipherSuites,
					PreferServerCipherSuites:    config.PreferServerCipherSuites,
					SessionTicketsDisabled:      config.SessionTicketsDisabled,
					SessionTicketKey:            config.SessionTicketKey,
					MinVersion:                  config.MinVersion,
					MaxVersion:                  config.MaxVersion,
					CurvePreferences:            castCurvesToUCurves(config.CurvePreferences),
					DynamicRecordSizingDisabled: config.DynamicRecordSizingDisabled,
					KeyLogWriter:                config.KeyLogWriter,
				}
			}
			return utls.UClient(c, ucfg, fp)
		}, nil
	}
	return func(c net.Conn, config *tls.Config) net.Conn {
		return tls.Client(c, config)
	}, nil
}

func castCertsToUCerts(certs []tls.Certificate) []utls.Certificate {
	if certs == nil {
		return nil
	}
	ucerts := make([]utls.Certificate, len(certs))
	for i, cert := range certs {
		ucerts[i] = utls.Certificate{
			Certificate:                  cert.Certificate,
			PrivateKey:                   cert.PrivateKey,
			SupportedSignatureAlgorithms: castSigSchemesToUSigSchemes(cert.SupportedSignatureAlgorithms),
			OCSPStaple:                   cert.OCSPStaple,
			SignedCertificateTimestamps:  cert.SignedCertificateTimestamps,
			Leaf:                         cert.Leaf,
		}
	}
	return ucerts
}

func castSigSchemesToUSigSchemes(schemes []tls.SignatureScheme) []utls.SignatureScheme {
	if schemes == nil {
		return nil
	}
	uschemes := make([]utls.SignatureScheme, len(schemes))
	for i, scheme := range schemes {
		uschemes[i] = utls.SignatureScheme(scheme)
	}
	return uschemes
}

func castCurvesToUCurves(curves []tls.CurveID) []utls.CurveID {
	if curves == nil {
		return nil
	}
	ucurves := make([]utls.CurveID, len(curves))
	for i, curve := range curves {
		ucurves[i] = utls.CurveID(curve)
	}
	return ucurves
}
