package main

import (
	"crypto/tls"
	"flag"
	"fmt"
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
	positionalArgs    []string
	proxy             []string
	sourceIPHints     string
	userIPHints       bool
}

func parse_args() CLIArgs {
	var args CLIArgs
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
	flag.Func("proxy", "upstream proxy URL. Can be repeated multiple times to chain proxies. Examples: socks5h://127.0.0.1:9050; https://user:password@example.com:443", func(p string) error {
		args.proxy = append(args.proxy, p)
		return nil
	})
	flag.StringVar(&args.sourceIPHints, "ip-hints", "", "a comma-separated list of source addresses to use on dial attempts. Example: \"10.0.0.1,fe80::2,0.0.0.0,::\"")
	flag.BoolVar(&args.userIPHints, "user-ip-hints", false, "allow IP hints to be specified by user in X-Src-IP-Hints header")
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

	logWriter := NewLogWriter(os.Stderr)
	defer logWriter.Close()

	mainLogger := NewCondLogger(log.New(logWriter, "MAIN    : ",
		log.LstdFlags|log.Lshortfile),
		args.verbosity)
	proxyLogger := NewCondLogger(log.New(logWriter, "PROXY   : ",
		log.LstdFlags|log.Lshortfile),
		args.verbosity)
	authLogger := NewCondLogger(log.New(logWriter, "AUTH    : ",
		log.LstdFlags|log.Lshortfile),
		args.verbosity)

	auth, err := NewAuth(args.auth, authLogger)
	if err != nil {
		mainLogger.Critical("Failed to instantiate auth provider: %v", err)
		return 3
	}
	defer auth.Stop()

	var dialer Dialer = NewBoundDialer(new(net.Dialer), args.sourceIPHints)
	for _, proxyURL := range args.proxy {
		newDialer, err := proxyDialerFromURL(proxyURL, dialer)
		if err != nil {
			mainLogger.Critical("Failed to create dialer for proxy %q: %v", proxyURL, err)
			return 3
		}
		dialer = newDialer
	}

	server := http.Server{
		Addr:              args.bind_address,
		Handler:           NewProxyHandler(args.timeout, auth, maybeWrapWithContextDialer(dialer), args.userIPHints, proxyLogger),
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
		cfg, err1 := makeServerTLSConfig(args.cert, args.key, args.cafile, args.ciphers, !args.disableHTTP2)
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
		cfg, err = updateServerTLSConfig(cfg, args.cafile, args.ciphers, !args.disableHTTP2)
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

func main() {
	os.Exit(run())
}
