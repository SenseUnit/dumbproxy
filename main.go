package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
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

type CLIArgs struct {
	bind_address      string
	auth              string
	verbosity         int
	timeout           time.Duration
	cert, key, cafile string
	list_ciphers      bool
	ciphers           string
}

func list_ciphers() {
	for _, cipher := range tls.CipherSuites() {
		fmt.Println(cipher.Name)
	}
}

func parse_args() CLIArgs {
	var args CLIArgs
	flag.StringVar(&args.bind_address, "bind-address", ":8080", "HTTP proxy listen address")
	flag.StringVar(&args.auth, "auth", "none://", "auth parameters")
	flag.IntVar(&args.verbosity, "verbosity", 20, "logging verbosity "+
		"(10 - debug, 20 - info, 30 - warning, 40 - error, 50 - critical)")
	flag.DurationVar(&args.timeout, "timeout", 10*time.Second, "timeout for network operations")
	flag.StringVar(&args.cert, "cert", "", "enable TLS and use certificate")
	flag.StringVar(&args.key, "key", "", "key for TLS certificate")
	flag.StringVar(&args.cafile, "cafile", "", "CA file to authenticate clients with certificates")
	flag.BoolVar(&args.list_ciphers, "list-ciphers", false, "list ciphersuites")
	flag.StringVar(&args.ciphers, "ciphers", "", "colon-separated list of enabled ciphers")
	flag.Parse()
	return args
}

func run() int {
	args := parse_args()

	if args.list_ciphers {
		list_ciphers()
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

	auth, err := NewAuth(args.auth)
	if err != nil {
		mainLogger.Critical("Failed to instantiate auth provider: %v", err)
		return 3
	}

	server := http.Server{
		Addr:              args.bind_address,
		Handler:           NewProxyHandler(args.timeout, auth, proxyLogger),
		ErrorLog:          log.New(logWriter, "HTTPSRV : ", log.LstdFlags|log.Lshortfile),
		ReadTimeout:       0,
		ReadHeaderTimeout: 0,
		WriteTimeout:      0,
		IdleTimeout:       0,
	}

	mainLogger.Info("Starting proxy server...")
	if args.cert != "" {
		cfg, err1 := makeServerTLSConfig(args.cert, args.key, args.cafile)
		if err1 != nil {
			mainLogger.Critical("TLS config construction failed: %v", err)
			return 3
		}
		cfg.CipherSuites = makeCipherList(args.ciphers)
		server.TLSConfig = cfg
		err = server.ListenAndServeTLS("", "")
	} else {
		err = server.ListenAndServe()
	}
	mainLogger.Critical("Server terminated with a reason: %v", err)
	mainLogger.Info("Shutting down...")
	return 0
}

func main() {
	os.Exit(run())
}
