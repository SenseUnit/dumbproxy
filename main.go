package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/coreos/go-systemd/v22/activation"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/SenseUnit/dumbproxy/auth"
	"github.com/SenseUnit/dumbproxy/dialer"
	"github.com/SenseUnit/dumbproxy/handler"
	clog "github.com/SenseUnit/dumbproxy/log"
)

var (
	home, _ = os.UserHomeDir()
	version = "undefined"
)

func perror(msg string) {
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, msg)
}

func arg_fail(msg string) {
	perror(msg)
	perror("Usage:")
	flag.PrintDefaults()
	os.Exit(2)
}

type CSVArg []string

func (a *CSVArg) Set(s string) error {
	*a = strings.Split(s, ",")
	return nil
}

func (a *CSVArg) String() string {
	if a == nil {
		return "<nil>"
	}
	if *a == nil {
		return "<empty>"
	}
	return strings.Join(*a, ",")
}

type TLSVersionArg uint16

func (a *TLSVersionArg) Set(s string) error {
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
		return fmt.Errorf("unknown TLS version %q", s)
	}
	*a = TLSVersionArg(ver)
	return nil
}

func (a *TLSVersionArg) String() string {
	switch *a {
	case tls.VersionTLS10:
		return "TLS10"
	case tls.VersionTLS11:
		return "TLS11"
	case tls.VersionTLS12:
		return "TLS12"
	case tls.VersionTLS13:
		return "TLS13"
	default:
		return fmt.Sprintf("%#04x", *a)
	}
}

type CLIArgs struct {
	bind_address      string
	auth              string
	verbosity         int
	timeout           time.Duration
	cert, key, cafile string
	list_ciphers      bool
	ciphers           string
	disableHTTP2      bool
	showVersion       bool
	autocert          bool
	autocertWhitelist CSVArg
	autocertDir       string
	autocertACME      string
	autocertEmail     string
	autocertHTTP      string
	passwd            string
	passwdCost        int
	hmacSign          bool
	hmacGenKey        bool
	positionalArgs    []string
	proxy             []string
	sourceIPHints     string
	userIPHints       bool
	minTLSVersion     TLSVersionArg
	maxTLSVersion     TLSVersionArg
}

func parse_args() CLIArgs {
	args := CLIArgs{
		minTLSVersion: TLSVersionArg(tls.VersionTLS12),
		maxTLSVersion: TLSVersionArg(tls.VersionTLS13),
	}
	flag.StringVar(&args.bind_address, "bind-address", ":8080", "HTTP proxy listen address. Set empty value to use systemd socket activation.")
	flag.StringVar(&args.auth, "auth", "none://", "auth parameters")
	flag.IntVar(&args.verbosity, "verbosity", 20, "logging verbosity "+
		"(10 - debug, 20 - info, 30 - warning, 40 - error, 50 - critical)")
	flag.DurationVar(&args.timeout, "timeout", 10*time.Second, "timeout for network operations")
	flag.StringVar(&args.cert, "cert", "", "enable TLS and use certificate")
	flag.StringVar(&args.key, "key", "", "key for TLS certificate")
	flag.StringVar(&args.cafile, "cafile", "", "CA file to authenticate clients with certificates")
	flag.BoolVar(&args.list_ciphers, "list-ciphers", false, "list ciphersuites")
	flag.StringVar(&args.ciphers, "ciphers", "", "colon-separated list of enabled ciphers")
	flag.BoolVar(&args.disableHTTP2, "disable-http2", false, "disable HTTP2")
	flag.BoolVar(&args.showVersion, "version", false, "show program version and exit")
	flag.BoolVar(&args.autocert, "autocert", false, "issue TLS certificates automatically")
	flag.Var(&args.autocertWhitelist, "autocert-whitelist", "restrict autocert domains to this comma-separated list")
	flag.StringVar(&args.autocertDir, "autocert-dir", filepath.Join(home, ".dumbproxy", "autocert"), "path to autocert cache")
	flag.StringVar(&args.autocertACME, "autocert-acme", autocert.DefaultACMEDirectory, "custom ACME endpoint")
	flag.StringVar(&args.autocertEmail, "autocert-email", "", "email used for ACME registration")
	flag.StringVar(&args.autocertHTTP, "autocert-http", "", "listen address for HTTP-01 challenges handler of ACME")
	flag.StringVar(&args.passwd, "passwd", "", "update given htpasswd file and add/set password for username. "+
		"Username and password can be passed as positional arguments or requested interactively")
	flag.IntVar(&args.passwdCost, "passwd-cost", bcrypt.MinCost, "bcrypt password cost (for -passwd mode)")
	flag.BoolVar(&args.hmacSign, "hmac-sign", false, "sign username with specified key for given validity period. "+
		"Positional arguments are: hex-encoded HMAC key, username, validity duration.")
	flag.BoolVar(&args.hmacGenKey, "hmac-genkey", false, "generate hex-encoded HMAC signing key of optimal length")
	flag.Func("proxy", "upstream proxy URL. Can be repeated multiple times to chain proxies. Examples: socks5h://127.0.0.1:9050; https://user:password@example.com:443", func(p string) error {
		args.proxy = append(args.proxy, p)
		return nil
	})
	flag.StringVar(&args.sourceIPHints, "ip-hints", "", "a comma-separated list of source addresses to use on dial attempts. \"$lAddr\" gets expanded to local address of connection. Example: \"10.0.0.1,fe80::2,$lAddr,0.0.0.0,::\"")
	flag.BoolVar(&args.userIPHints, "user-ip-hints", false, "allow IP hints to be specified by user in X-Src-IP-Hints header")
	flag.Var(&args.minTLSVersion, "min-tls-version", "minimal TLS version accepted by server")
	flag.Var(&args.maxTLSVersion, "max-tls-version", "maximum TLS version accepted by server")
	flag.Parse()
	args.positionalArgs = flag.Args()
	return args
}

func run() int {
	args := parse_args()

	if args.showVersion {
		fmt.Println(version)
		return 0
	}

	if args.list_ciphers {
		list_ciphers()
		return 0
	}

	if args.passwd != "" {
		if err := passwd(args.passwd, args.passwdCost, args.positionalArgs...); err != nil {
			log.Fatalf("can't set password: %v", err)
		}
		return 0
	}

	if args.hmacSign {
		if err := hmacSign(args.positionalArgs...); err != nil {
			log.Fatalf("can't sign: %v", err)
		}
		return 0
	}

	if args.hmacGenKey {
		if err := hmacGenKey(); err != nil {
			log.Fatalf("can't generate key: %v", err)
		}
		return 0
	}

	logWriter := clog.NewLogWriter(os.Stderr)
	defer logWriter.Close()

	mainLogger := clog.NewCondLogger(log.New(logWriter, "MAIN    : ",
		log.LstdFlags|log.Lshortfile),
		args.verbosity)
	proxyLogger := clog.NewCondLogger(log.New(logWriter, "PROXY   : ",
		log.LstdFlags|log.Lshortfile),
		args.verbosity)
	authLogger := clog.NewCondLogger(log.New(logWriter, "AUTH    : ",
		log.LstdFlags|log.Lshortfile),
		args.verbosity)

	auth, err := auth.NewAuth(args.auth, authLogger)
	if err != nil {
		mainLogger.Critical("Failed to instantiate auth provider: %v", err)
		return 3
	}
	defer auth.Stop()

	var d dialer.Dialer = dialer.NewBoundDialer(new(net.Dialer), args.sourceIPHints)
	for _, proxyURL := range args.proxy {
		newDialer, err := dialer.ProxyDialerFromURL(proxyURL, d)
		if err != nil {
			mainLogger.Critical("Failed to create dialer for proxy %q: %v", proxyURL, err)
			return 3
		}
		d = newDialer
	}

	server := http.Server{
		Addr: args.bind_address,
		Handler: handler.NewProxyHandler(
			args.timeout,
			auth,
			dialer.MaybeWrapWithContextDialer(d),
			args.userIPHints,
			proxyLogger),
		ErrorLog:          log.New(logWriter, "HTTPSRV : ", log.LstdFlags|log.Lshortfile),
		ReadTimeout:       0,
		ReadHeaderTimeout: 0,
		WriteTimeout:      0,
		IdleTimeout:       0,
	}

	if args.disableHTTP2 {
		server.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	}

	mainLogger.Info("Starting proxy server...")
	var listener net.Listener
	if args.bind_address == "" {
		// socket activation
		listeners, err := activation.Listeners()
		if err != nil {
			mainLogger.Critical("socket activation failed: %v", err)
			return 3
		}
		if len(listeners) != 1 {
			mainLogger.Critical("socket activation failed: unexpected number of listeners: %d",
				len(listeners))
			return 3
		}
		if listeners[0] == nil {
			mainLogger.Critical("socket activation failed: nil listener returned")
			return 3
		}
		listener = listeners[0]
	} else {
		newListener, err := net.Listen("tcp", args.bind_address)
		if err != nil {
			mainLogger.Critical("listen failed: %v", err)
			return 3
		}
		listener = newListener
	}

	if args.cert != "" {
		cfg, err1 := makeServerTLSConfig(args.cert, args.key, args.cafile,
			args.ciphers, uint16(args.minTLSVersion), uint16(args.maxTLSVersion), !args.disableHTTP2)
		if err1 != nil {
			mainLogger.Critical("TLS config construction failed: %v", err1)
			return 3
		}
		listener = tls.NewListener(listener, cfg)
	} else if args.autocert {
		m := &autocert.Manager{
			Cache:  autocert.DirCache(args.autocertDir),
			Prompt: autocert.AcceptTOS,
			Client: &acme.Client{DirectoryURL: args.autocertACME},
			Email:  args.autocertEmail,
		}
		if args.autocertWhitelist != nil {
			m.HostPolicy = autocert.HostWhitelist([]string(args.autocertWhitelist)...)
		}
		if args.autocertHTTP != "" {
			go func() {
				log.Fatalf("HTTP-01 ACME challenge server stopped: %v",
					http.ListenAndServe(args.autocertHTTP, m.HTTPHandler(nil)))
			}()
		}
		cfg := m.TLSConfig()
		cfg, err = updateServerTLSConfig(cfg, args.cafile, args.ciphers,
			uint16(args.minTLSVersion), uint16(args.maxTLSVersion), !args.disableHTTP2)
		if err != nil {
			mainLogger.Critical("TLS config construction failed: %v", err)
			return 3
		}
		listener = tls.NewListener(listener, cfg)
	}
	mainLogger.Info("Proxy server started.")
	err = server.Serve(listener)
	mainLogger.Critical("Server terminated with a reason: %v", err)
	mainLogger.Info("Shutting down...")
	return 0
}

func makeServerTLSConfig(certfile, keyfile, cafile, ciphers string, minVer, maxVer uint16, h2 bool) (*tls.Config, error) {
	cfg := tls.Config{
		MinVersion: minVer,
		MaxVersion: maxVer,
	}
	cert, err := tls.LoadX509KeyPair(certfile, keyfile)
	if err != nil {
		return nil, err
	}
	cfg.Certificates = []tls.Certificate{cert}
	if cafile != "" {
		roots := x509.NewCertPool()
		certs, err := ioutil.ReadFile(cafile)
		if err != nil {
			return nil, err
		}
		if ok := roots.AppendCertsFromPEM(certs); !ok {
			return nil, errors.New("Failed to load CA certificates")
		}
		cfg.ClientCAs = roots
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
	}
	cfg.CipherSuites = makeCipherList(ciphers)
	if h2 {
		cfg.NextProtos = []string{"h2", "http/1.1"}
	} else {
		cfg.NextProtos = []string{"http/1.1"}
	}
	return &cfg, nil
}

func updateServerTLSConfig(cfg *tls.Config, cafile, ciphers string, minVer, maxVer uint16, h2 bool) (*tls.Config, error) {
	if cafile != "" {
		roots := x509.NewCertPool()
		certs, err := ioutil.ReadFile(cafile)
		if err != nil {
			return nil, err
		}
		if ok := roots.AppendCertsFromPEM(certs); !ok {
			return nil, errors.New("Failed to load CA certificates")
		}
		cfg.ClientCAs = roots
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
	}
	cfg.CipherSuites = makeCipherList(ciphers)
	if h2 {
		cfg.NextProtos = []string{"h2", "http/1.1", "acme-tls/1"}
	} else {
		cfg.NextProtos = []string{"http/1.1", "acme-tls/1"}
	}
	cfg.MinVersion = minVer
	cfg.MaxVersion = maxVer
	return cfg, nil
}

func makeCipherList(ciphers string) []uint16 {
	if ciphers == "" {
		return nil
	}

	cipherIDs := make(map[string]uint16)
	for _, cipher := range tls.CipherSuites() {
		cipherIDs[cipher.Name] = cipher.ID
	}

	cipherNameList := strings.Split(ciphers, ":")
	cipherIDList := make([]uint16, 0, len(cipherNameList))

	for _, name := range cipherNameList {
		id, ok := cipherIDs[name]
		if !ok {
			log.Printf("WARNING: Unknown cipher \"%s\"", name)
		}
		cipherIDList = append(cipherIDList, id)
	}

	return cipherIDList
}

func list_ciphers() {
	for _, cipher := range tls.CipherSuites() {
		fmt.Println(cipher.Name)
	}
}

func passwd(filename string, cost int, args ...string) error {
	var (
		username, password, password2 string
		err                           error
	)

	if len(args) > 0 {
		username = args[0]
	} else {
		username, err = prompt("Enter username: ", false)
		if err != nil {
			return fmt.Errorf("can't get username: %w", err)
		}
	}

	if len(args) > 1 {
		password = args[1]
	} else {
		password, err = prompt("Enter password: ", true)
		if err != nil {
			return fmt.Errorf("can't get password: %w", err)
		}
		password2, err = prompt("Repeat password: ", true)
		if err != nil {
			return fmt.Errorf("can't get password (repeat): %w", err)
		}
		if password != password2 {
			return fmt.Errorf("passwords do not match")
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return fmt.Errorf("can't generate password hash: %w", err)
	}

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("can't open file: %w", err)
	}
	defer f.Close()

	_, err = f.WriteString(fmt.Sprintf("%s:%s\n", username, hash))
	if err != nil {
		return fmt.Errorf("can't write to file: %w", err)
	}

	return nil
}

func hmacSign(args ...string) error {
	if len(args) != 3 {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "dumbproxy -hmac-sign <HMAC key> <username> <validity duration>")
		fmt.Fprintln(os.Stderr, "")
		return errors.New("bad command line arguments")
	}

	secret, err := hex.DecodeString(args[0])
	if err != nil {
		return fmt.Errorf("unable to hex-decode HMAC secret: %w", err)
	}

	validity, err := time.ParseDuration(args[2])
	if err != nil {
		return fmt.Errorf("unable to parse validity duration: %w", err)
	}

	expire := time.Now().Add(validity).Unix()
	mac := auth.CalculateHMACSignature(secret, args[1], expire)
	token := auth.HMACToken{
		Expire: expire,
	}
	copy(token.Signature[:], mac)

	var resBuf bytes.Buffer
	enc := base64.NewEncoder(base64.RawURLEncoding, &resBuf)
	if err := binary.Write(enc, binary.BigEndian, &token); err != nil {
		return fmt.Errorf("token encoding failed: %w", err)
	}
	enc.Close()

	fmt.Println("Username:", args[1])
	fmt.Println("Password:", resBuf.String())
	return nil
}

func hmacGenKey(args ...string) error {
	buf := make([]byte, auth.HMACSignatureSize)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Errorf("CSPRNG failure: %w", err)
	}
	fmt.Println(hex.EncodeToString(buf))
	return nil
}

func prompt(prompt string, secure bool) (string, error) {
	var input string
	fmt.Print(prompt)

	if secure {
		b, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", err
		}
		input = string(b)
		fmt.Println()
	} else {
		fmt.Scanln(&input)
	}
	return input, nil
}

func main() {
	os.Exit(run())
}
