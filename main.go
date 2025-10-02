package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/activation"
	"github.com/libp2p/go-reuseport"
	"github.com/things-go/go-socks5"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/SenseUnit/dumbproxy/access"
	"github.com/SenseUnit/dumbproxy/auth"
	"github.com/SenseUnit/dumbproxy/certcache"
	"github.com/SenseUnit/dumbproxy/dialer"
	"github.com/SenseUnit/dumbproxy/forward"
	"github.com/SenseUnit/dumbproxy/handler"
	clog "github.com/SenseUnit/dumbproxy/log"
	"github.com/SenseUnit/dumbproxy/resolver"
	"github.com/SenseUnit/dumbproxy/tlsutil"
	proxyproto "github.com/pires/go-proxyproto"

	_ "golang.org/x/crypto/x509roots/fallback"
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

type CSVArg struct {
	values []string
}

func (a *CSVArg) String() string {
	if len(a.values) == 0 {
		return ""
	}
	buf := new(bytes.Buffer)
	wr := csv.NewWriter(buf)
	wr.Write(a.values)
	wr.Flush()
	return strings.TrimRight(buf.String(), "\n")
}

func (a *CSVArg) Set(line string) error {
	if line == "" {
		a.values = nil
		return nil
	}
	rd := csv.NewReader(strings.NewReader(line))
	rd.FieldsPerRecord = -1
	rd.TrimLeadingSpace = true
	rd.ReuseRecord = true
	values, err := rd.Read()
	if err == io.EOF {
		a.values = nil
		return nil
	}
	if err != nil {
		return fmt.Errorf("unable to parse comma-separated argument: %w", err)
	}
	a.values = values
	return nil
}

type PrefixList []netip.Prefix

func (l *PrefixList) Set(s string) error {
	var pfxList []netip.Prefix
	parts := strings.Split(s, ",")
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		pfx, err := netip.ParsePrefix(part)
		if err != nil {
			return fmt.Errorf("unable to parse prefix list element %d (%q): %w", i, part, err)
		}
		pfxList = append(pfxList, pfx)
	}
	*l = PrefixList(pfxList)
	return nil
}

func (l *PrefixList) String() string {
	if l == nil || *l == nil {
		return ""
	}
	parts := make([]string, 0, len([]netip.Prefix(*l)))
	for _, part := range []netip.Prefix(*l) {
		parts = append(parts, part.String())
	}
	return strings.Join(parts, ", ")
}

func (l *PrefixList) Value() []netip.Prefix {
	return []netip.Prefix(*l)
}

type TLSVersionArg uint16

func (a *TLSVersionArg) Set(s string) error {
	ver, err := tlsutil.ParseVersion(s)
	if err != nil {
		return err
	}
	*a = TLSVersionArg(ver)
	return nil
}

func (a *TLSVersionArg) String() string {
	return tlsutil.FormatVersion(uint16(*a))
}

type proxyArg struct {
	literal bool
	value   string
}

type hexArg struct {
	value []byte
}

func (a *hexArg) String() string {
	return hex.EncodeToString(a.value)
}

func (a *hexArg) Set(s string) error {
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	a.value = b
	return nil
}

func (a *hexArg) Value() []byte {
	return a.value
}

type modeArg fs.FileMode

func (a *modeArg) String() string {
	return fmt.Sprintf("%#o", uint32(*a))
}

func (a *modeArg) Set(s string) error {
	p, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return err
	}
	*a = modeArg(p)
	return nil
}

func (a *modeArg) Value() fs.FileMode {
	return fs.FileMode(*a)
}

type cacheKind int

const (
	cacheKindDir cacheKind = iota
	cacheKindRedis
	cacheKindRedisCluster
)

type autocertCache struct {
	kind  cacheKind
	value string
}

type proxyMode int

const (
	_ proxyMode = iota
	proxyModeHTTP
	proxyModeSOCKS5
)

type proxyModeArg struct {
	value proxyMode
}

func (a *proxyModeArg) Set(arg string) error {
	var val proxyMode
	switch s := strings.ToLower(arg); s {
	case "http", "https":
		val = proxyModeHTTP
	case "socks", "socks5":
		val = proxyModeSOCKS5
	default:
		return fmt.Errorf("unrecognized proxy mode %q", arg)
	}
	a.value = val
	return nil
}

func (a *proxyModeArg) String() string {
	switch a.value {
	case proxyModeHTTP:
		return "http"
	case proxyModeSOCKS5:
		return "socks5"
	default:
		return fmt.Sprintf("proxyMode(%d)", int(a.value))
	}
}

const envCacheEncKey = "DUMBPROXY_CACHE_ENC_KEY"

type dnsPreferenceArg resolver.Preference

func (a *dnsPreferenceArg) String() string {
	return resolver.Preference(*a).String()
}

func (a *dnsPreferenceArg) Set(s string) error {
	p, err := resolver.ParsePreference(s)
	if err != nil {
		return nil
	}
	*a = dnsPreferenceArg(p)
	return nil
}

func (a *dnsPreferenceArg) Value() resolver.Preference {
	return resolver.Preference(*a)
}

type bindSpec struct {
	af      string
	address string
}

type CLIArgs struct {
	bind                      bindSpec
	bindReusePort             bool
	bindPprof                 bindSpec
	unixSockUnlink            bool
	unixSockMode              modeArg
	mode                      proxyModeArg
	auth                      string
	verbosity                 int
	cert, key, cafile         string
	list_ciphers              bool
	list_curves               bool
	ciphers                   string
	curves                    string
	disableHTTP2              bool
	showVersion               bool
	autocert                  bool
	autocertWhitelist         CSVArg
	autocertCache             autocertCache
	autocertCacheRedisPrefix  string
	autocertACME              string
	autocertEmail             string
	autocertHTTP              string
	autocertLocalCacheTTL     time.Duration
	autocertLocalCacheTimeout time.Duration
	autocertCacheEncKey       hexArg
	passwd                    string
	passwdCost                int
	hmacSign                  bool
	hmacGenKey                bool
	positionalArgs            []string
	proxy                     []proxyArg
	sourceIPHints             string
	userIPHints               bool
	minTLSVersion             TLSVersionArg
	maxTLSVersion             TLSVersionArg
	tlsALPNEnabled            bool
	tlsALPNProtos             CSVArg
	bwLimit                   uint64
	bwBurst                   int64
	bwBuckets                 uint
	bwSeparate                bool
	dnsServers                []string
	dnsPreferAddress          dnsPreferenceArg
	dnsCacheTTL               time.Duration
	dnsCacheNegTTL            time.Duration
	dnsCacheTimeout           time.Duration
	reqHeaderTimeout          time.Duration
	denyDstAddr               PrefixList
	jsAccessFilter            string
	jsAccessFilterInstances   int
	jsProxyRouterInstances    int
	proxyproto                bool
	shutdownTimeout           time.Duration
}

func parse_args() *CLIArgs {
	args := &CLIArgs{
		minTLSVersion: TLSVersionArg(tls.VersionTLS12),
		maxTLSVersion: TLSVersionArg(tls.VersionTLS13),
		denyDstAddr: PrefixList{
			netip.MustParsePrefix("127.0.0.0/8"),
			netip.MustParsePrefix("0.0.0.0/32"),
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("172.16.0.0/12"),
			netip.MustParsePrefix("192.168.0.0/16"),
			netip.MustParsePrefix("169.254.0.0/16"),
			netip.MustParsePrefix("::1/128"),
			netip.MustParsePrefix("::/128"),
			netip.MustParsePrefix("fe80::/10"),
		},
		autocertCache: autocertCache{
			kind:  cacheKindDir,
			value: filepath.Join(home, ".dumbproxy", "autocert"),
		},
		bind: bindSpec{
			address: ":8080",
			af:      "tcp",
		},
		mode:             proxyModeArg{proxyModeHTTP},
		dnsPreferAddress: dnsPreferenceArg(resolver.PreferenceIPv4),
	}
	args.autocertCacheEncKey.Set(os.Getenv(envCacheEncKey))
	flag.Func("bind-address", "HTTP proxy listen address. Set empty value to use systemd socket activation. (default \":8080\")", func(p string) error {
		args.bind.address = p
		args.bind.af = "tcp"
		return nil
	})
	flag.Func("bind-unix-socket", "Unix domain socket to listen to, overrides bind-address if set.", func(p string) error {
		args.bind.address = p
		args.bind.af = "unix"
		return nil
	})
	flag.BoolVar(&args.bindReusePort, "bind-reuseport", false, "allow multiple server instances on the same port")
	flag.Func("bind-pprof", "enables pprof debug endpoints", func(p string) error {
		args.bindPprof.address = p
		args.bindPprof.af = "tcp"
		return nil
	})
	flag.Func("bind-pprof-unix-socket", "enables pprof debug endpoints listening on Unix domain socket", func(p string) error {
		args.bindPprof.address = p
		args.bindPprof.af = "unix"
		return nil
	})
	flag.BoolVar(&args.unixSockUnlink, "unix-sock-unlink", true, "delete file object located at Unix domain socket bind path before binding")
	flag.Var(&args.unixSockMode, "unix-sock-mode", "set file mode for bound unix socket")
	flag.Var(&args.mode, "mode", "proxy operation mode (http/socks5)")
	flag.StringVar(&args.auth, "auth", "none://", "auth parameters")
	flag.IntVar(&args.verbosity, "verbosity", 20, "logging verbosity "+
		"(10 - debug, 20 - info, 30 - warning, 40 - error, 50 - critical)")
	flag.StringVar(&args.cert, "cert", "", "enable TLS and use certificate")
	flag.StringVar(&args.key, "key", "", "key for TLS certificate")
	flag.StringVar(&args.cafile, "cafile", "", "CA file to authenticate clients with certificates")
	flag.BoolVar(&args.list_ciphers, "list-ciphers", false, "list ciphersuites")
	flag.BoolVar(&args.list_curves, "list-curves", false, "list key exchange curves")
	flag.StringVar(&args.ciphers, "ciphers", "", "colon-separated list of enabled ciphers")
	flag.StringVar(&args.curves, "curves", "", "colon-separated list of enabled key exchange curves")
	flag.BoolVar(&args.disableHTTP2, "disable-http2", false, "disable HTTP2")
	flag.BoolVar(&args.showVersion, "version", false, "show program version and exit")
	flag.BoolVar(&args.autocert, "autocert", false, "issue TLS certificates automatically")
	flag.Var(&args.autocertWhitelist, "autocert-whitelist", "restrict autocert domains to this comma-separated list")
	flag.Func("autocert-dir", "use directory path for autocert cache", func(p string) error {
		args.autocertCache = autocertCache{
			kind:  cacheKindDir,
			value: p,
		}
		return nil
	})
	flag.Func("autocert-cache-redis", "use Redis URL for autocert cache", func(p string) error {
		args.autocertCache = autocertCache{
			kind:  cacheKindRedis,
			value: p,
		}
		return nil
	})
	flag.Func("autocert-cache-redis-cluster", "use Redis Cluster URL for autocert cache", func(p string) error {
		args.autocertCache = autocertCache{
			kind:  cacheKindRedisCluster,
			value: p,
		}
		return nil
	})
	flag.StringVar(&args.autocertCacheRedisPrefix, "autocert-cache-redis-prefix", "", "prefix to use for keys in Redis or Redis Cluster cache")
	flag.Var(&args.autocertCacheEncKey, "autocert-cache-enc-key", "hex-encoded encryption key for cert cache entries. Can be also set with "+envCacheEncKey+" environment variable")
	flag.StringVar(&args.autocertACME, "autocert-acme", autocert.DefaultACMEDirectory, "custom ACME endpoint")
	flag.StringVar(&args.autocertEmail, "autocert-email", "", "email used for ACME registration")
	flag.StringVar(&args.autocertHTTP, "autocert-http", "", "listen address for HTTP-01 challenges handler of ACME")
	flag.DurationVar(&args.autocertLocalCacheTTL, "autocert-local-cache-ttl", 0, "enables in-memory cache for certificates")
	flag.DurationVar(&args.autocertLocalCacheTimeout, "autocert-local-cache-timeout", 10*time.Second, "timeout for cert cache queries")
	flag.StringVar(&args.passwd, "passwd", "", "update given htpasswd file and add/set password for username. "+
		"Username and password can be passed as positional arguments or requested interactively")
	flag.IntVar(&args.passwdCost, "passwd-cost", bcrypt.MinCost, "bcrypt password cost (for -passwd mode)")
	flag.BoolVar(&args.hmacSign, "hmac-sign", false, "sign username with specified key for given validity period. "+
		"Positional arguments are: hex-encoded HMAC key, username, validity duration.")
	flag.BoolVar(&args.hmacGenKey, "hmac-genkey", false, "generate hex-encoded HMAC signing key of optimal length")
	flag.Func("proxy", "upstream proxy URL. Can be repeated multiple times to chain proxies. Examples: socks5h://127.0.0.1:9050; https://user:password@example.com:443", func(p string) error {
		args.proxy = append(args.proxy, proxyArg{true, p})
		return nil
	})
	flag.StringVar(&args.sourceIPHints, "ip-hints", "", "a comma-separated list of source addresses to use on dial attempts. \"$lAddr\" gets expanded to local address of connection. Example: \"10.0.0.1,fe80::2,$lAddr,0.0.0.0,::\"")
	flag.BoolVar(&args.userIPHints, "user-ip-hints", false, "allow IP hints to be specified by user in X-Src-IP-Hints header")
	flag.Var(&args.minTLSVersion, "min-tls-version", "minimum TLS version accepted by server")
	flag.Var(&args.maxTLSVersion, "max-tls-version", "maximum TLS version accepted by server")
	flag.BoolVar(&args.tlsALPNEnabled, "tls-alpn-enabled", true, "enable application protocol negotiation with TLS ALPN extension")
	flag.Var(&args.tlsALPNProtos, "tls-alpn-protos", "comma-separated values (RFC 4180) of enabled ALPN identities")
	flag.Uint64Var(&args.bwLimit, "bw-limit", 0, "per-user bandwidth limit in bytes per second")
	flag.Int64Var(&args.bwBurst, "bw-limit-burst", 0, "allowed burst size for bandwidth limit, how many \"tokens\" can fit into leaky bucket")
	flag.UintVar(&args.bwBuckets, "bw-limit-buckets", 1024*1024, "number of buckets of bandwidth limit")
	flag.BoolVar(&args.bwSeparate, "bw-limit-separate", false, "separate upload and download bandwidth limits")
	flag.Func("dns-server", "nameserver specification (udp://..., tcp://..., https://..., tls://..., doh://..., dot://..., default://). Option can be used multiple times for parallel use of multiple nameservers. Empty string resets the list", func(p string) error {
		if p == "" {
			args.dnsServers = nil
		} else {
			args.dnsServers = append(args.dnsServers, p)
		}
		return nil
	})
	flag.Var(&args.dnsPreferAddress, "dns-prefer-address", "address resolution preference (none/ipv4/ipv6)")
	flag.DurationVar(&args.dnsCacheTTL, "dns-cache-ttl", 0, "enable DNS cache with specified fixed TTL")
	flag.DurationVar(&args.dnsCacheNegTTL, "dns-cache-neg-ttl", time.Second, "TTL for negative responses of DNS cache")
	flag.DurationVar(&args.dnsCacheTimeout, "dns-cache-timeout", 5*time.Second, "timeout for shared resolves of DNS cache")
	flag.DurationVar(&args.reqHeaderTimeout, "req-header-timeout", 30*time.Second, "amount of time allowed to read request headers")
	flag.Var(&args.denyDstAddr, "deny-dst-addr", "comma-separated list of CIDR prefixes of forbidden IP addresses")
	flag.StringVar(&args.jsAccessFilter, "js-access-filter", "", "path to JS script file with the \"access\" filter function")
	flag.IntVar(&args.jsAccessFilterInstances, "js-access-filter-instances", runtime.GOMAXPROCS(0), "number of JS VM instances to handle access filter requests")
	flag.IntVar(&args.jsProxyRouterInstances, "js-proxy-router-instances", runtime.GOMAXPROCS(0), "number of JS VM instances to handle proxy router requests")
	flag.Func("js-proxy-router", "path to JS script file with the \"getProxy\" function", func(p string) error {
		args.proxy = append(args.proxy, proxyArg{false, p})
		return nil
	})
	flag.BoolVar(&args.proxyproto, "proxyproto", false, "listen proxy protocol")
	flag.DurationVar(&args.shutdownTimeout, "shutdown-timeout", 1*time.Second, "grace period during server shutdown")
	flag.Func("config", "read configuration from file with space-separated keys and values", readConfig)
	flag.Parse()
	args.positionalArgs = flag.Args()
	return args
}

func run() int {
	args := parse_args()

	// handle special invocation modes
	if args.showVersion {
		fmt.Println(version)
		return 0
	}

	if args.list_ciphers {
		list_ciphers()
		return 0
	}

	if args.list_curves {
		list_curves()
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

	// we don't expect positional arguments in the main operation mode
	if len(args.positionalArgs) > 0 {
		arg_fail("Unexpected positional arguments! Check your command line.")
	}

	// setup logging
	logWriter := clog.NewLogWriter(os.Stderr, 128)
	defer func() {
		ctx, cl := context.WithTimeout(context.Background(), 1*time.Second)
		defer cl()
		logWriter.Close(ctx)
	}()

	mainLogger := clog.NewCondLogger(log.New(logWriter, "MAIN    : ",
		log.LstdFlags|log.Lshortfile),
		args.verbosity)
	proxyLogger := clog.NewCondLogger(log.New(logWriter, "PROXY   : ",
		log.LstdFlags|log.Lshortfile),
		args.verbosity)
	authLogger := clog.NewCondLogger(log.New(logWriter, "AUTH    : ",
		log.LstdFlags|log.Lshortfile),
		args.verbosity)
	jsAccessLogger := clog.NewCondLogger(log.New(logWriter, "JSACCESS: ",
		log.LstdFlags|log.Lshortfile),
		args.verbosity)
	jsRouterLogger := clog.NewCondLogger(log.New(logWriter, "JSROUTER: ",
		log.LstdFlags|log.Lshortfile),
		args.verbosity)

	// setup auth provider
	authProvider, err := auth.NewAuth(args.auth, authLogger)
	if err != nil {
		mainLogger.Critical("Failed to instantiate auth provider: %v", err)
		return 3
	}
	defer authProvider.Stop()

	// setup access filters
	var filterRoot access.Filter = access.AlwaysAllow{}
	if args.jsAccessFilter != "" {
		j, err := access.NewJSFilter(
			args.jsAccessFilter,
			args.jsAccessFilterInstances,
			jsAccessLogger,
			filterRoot,
		)
		if err != nil {
			mainLogger.Critical("Failed to run JS filter: %v", err)
			return 3
		}
		filterRoot = j
	}
	if len(args.denyDstAddr.Value()) > 0 {
		filterRoot = access.NewDstAddrFilter(args.denyDstAddr.Value(), filterRoot)
	}

	// construct dialers
	var dialerRoot dialer.Dialer = dialer.NewBoundDialer(new(net.Dialer), args.sourceIPHints)
	if len(args.proxy) > 0 {
		for _, proxy := range args.proxy {
			if proxy.literal {
				newDialer, err := dialer.ProxyDialerFromURL(proxy.value, dialerRoot)
				if err != nil {
					mainLogger.Critical("Failed to create dialer for proxy %q: %v", proxy.value, err)
					return 3
				}
				dialerRoot = newDialer
			} else {
				newDialer, err := dialer.NewJSRouter(
					proxy.value,
					args.jsProxyRouterInstances,
					func(root dialer.Dialer) func(url string) (dialer.Dialer, error) {
						return func(url string) (dialer.Dialer, error) {
							return dialer.ProxyDialerFromURL(url, root)
						}
					}(dialerRoot),
					jsRouterLogger,
					dialerRoot,
				)
				if err != nil {
					mainLogger.Critical("Failed to create JS proxy router: %v", err)
					return 3
				}
				dialerRoot = newDialer
			}
		}
	}

	dialerRoot = dialer.NewFilterDialer(filterRoot.Access, dialerRoot) // must follow after resolving in chain

	var nameResolver dialer.Resolver = net.DefaultResolver
	if len(args.dnsServers) > 0 {
		nameResolver, err = resolver.FastFromURLs(args.dnsServers...)
		if err != nil {
			mainLogger.Critical("Failed to create name resolver: %v", err)
			return 3
		}
	}
	nameResolver = resolver.Prefer(nameResolver, args.dnsPreferAddress.Value())
	if args.dnsCacheTTL > 0 {
		cd := dialer.NewNameResolveCachingDialer(
			dialerRoot,
			nameResolver,
			args.dnsCacheTTL,
			args.dnsCacheNegTTL,
			args.dnsCacheTimeout,
		)
		cd.Start()
		defer cd.Stop()
		dialerRoot = cd
	} else {
		dialerRoot = dialer.NewNameResolvingDialer(dialerRoot, nameResolver)
	}

	// handler requisites
	forwarder := forward.PairConnections
	if args.bwLimit != 0 {
		forwarder = forward.NewBWLimit(
			float64(args.bwLimit),
			args.bwBurst,
			args.bwBuckets,
			args.bwSeparate,
		).PairConnections
	}

	stopContext, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	mainLogger.Info("Starting proxy server...")

	listenerFactory := net.Listen
	if args.bindReusePort {
		if reuseport.Available() {
			listenerFactory = reuseport.Listen
		} else {
			mainLogger.Warning("reuseport was requested but not available!")
		}
	}
	if args.unixSockUnlink {
		listenerFactory = func(orig func(string, string) (net.Listener, error)) func(string, string) (net.Listener, error) {
			return func(network, address string) (net.Listener, error) {
				if (network == "unix" || network == "unixdgram") && len(address) > 0 && address[0] != '@' {
					os.Remove(address)
				}
				return orig(network, address)
			}
		}(listenerFactory)
	}
	if args.unixSockMode != 0 {
		listenerFactory = func(orig func(string, string) (net.Listener, error)) func(string, string) (net.Listener, error) {
			return func(network, address string) (net.Listener, error) {
				if (network == "unix" || network == "unixdgram") && len(address) > 0 && address[0] != '@' {
					defer os.Chmod(address, args.unixSockMode.Value())
				}
				return orig(network, address)
			}
		}(listenerFactory)
	}

	var listener net.Listener
	if args.bind.address == "" {
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
		newListener, err := listenerFactory(args.bind.af, args.bind.address)
		if err != nil {
			mainLogger.Critical("listen failed: %v", err)
			return 3
		}
		listener = newListener
	}

	if args.proxyproto {
		mainLogger.Info("Listening proxy protocol")
		listener = &proxyproto.Listener{Listener: listener}
	}

	if args.cert != "" {
		cfg, err1 := makeServerTLSConfig(args)
		if err1 != nil {
			mainLogger.Critical("TLS config construction failed: %v", err1)
			return 3
		}
		listener = tls.NewListener(listener, cfg)
	} else if args.autocert {
		// cert caching chain
		var certCache autocert.Cache
		switch args.autocertCache.kind {
		case cacheKindDir:
			certCache = autocert.DirCache(args.autocertCache.value)
		case cacheKindRedis:
			certCache, err = certcache.RedisCacheFromURL(args.autocertCache.value, args.autocertCacheRedisPrefix)
			if err != nil {
				mainLogger.Critical("redis cache construction failed: %v", err)
				return 3
			}
		case cacheKindRedisCluster:
			certCache, err = certcache.RedisClusterCacheFromURL(args.autocertCache.value, args.autocertCacheRedisPrefix)
			if err != nil {
				mainLogger.Critical("redis cluster cache construction failed: %v", err)
				return 3
			}
		}
		if len(args.autocertCacheEncKey.Value()) > 0 {
			certCache, err = certcache.NewEncryptedCache(args.autocertCacheEncKey.Value(), certCache)
			if err != nil {
				mainLogger.Critical("unable to construct cache encryption layer: %v", err)
				return 3
			}
		}
		if args.autocertLocalCacheTTL > 0 {
			lcc := certcache.NewLocalCertCache(
				certCache,
				args.autocertLocalCacheTTL,
				args.autocertLocalCacheTimeout,
			)
			lcc.Start()
			defer lcc.Stop()
			certCache = lcc
		}

		m := &autocert.Manager{
			Cache:  certCache,
			Prompt: autocert.AcceptTOS,
			Client: &acme.Client{DirectoryURL: args.autocertACME},
			Email:  args.autocertEmail,
		}
		if args.autocertWhitelist.values != nil {
			m.HostPolicy = autocert.HostWhitelist(args.autocertWhitelist.values...)
		}
		if args.autocertHTTP != "" {
			go func() {
				mainLogger.Critical("HTTP-01 ACME challenge server stopped: %v",
					http.ListenAndServe(args.autocertHTTP, m.HTTPHandler(nil)))
			}()
		}
		cfg, err := makeServerTLSConfig(args)
		if err != nil {
			mainLogger.Critical("TLS config construction failed: %v", err)
			return 3
		}
		cfg.GetCertificate = m.GetCertificate
		if len(cfg.NextProtos) > 0 {
			cfg.NextProtos = append(cfg.NextProtos, acme.ALPNProto)
		}
		listener = tls.NewListener(listener, cfg)
	}
	defer listener.Close()

	// debug endpoints setup
	if args.bindPprof.address != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		pprofListener, err := listenerFactory(args.bindPprof.af, args.bindPprof.address)
		if err == nil {
			go func() { log.Fatal(http.Serve(pprofListener, mux)) }()
		}
	}

	mainLogger.Info("Proxy server started.")

	switch args.mode.value {
	case proxyModeHTTP:
		server := http.Server{
			Handler: handler.NewProxyHandler(&handler.Config{
				Dialer:      dialerRoot,
				Auth:        authProvider,
				Logger:      proxyLogger,
				UserIPHints: args.userIPHints,
				Forward:     forwarder,
			}),
			ErrorLog:          log.New(logWriter, "HTTPSRV : ", log.LstdFlags|log.Lshortfile),
			ReadTimeout:       0,
			ReadHeaderTimeout: args.reqHeaderTimeout,
			WriteTimeout:      0,
			IdleTimeout:       0,
			Protocols:         new(http.Protocols),
			BaseContext: func(_ net.Listener) context.Context {
				return stopContext
			},
		}
		if args.disableHTTP2 {
			server.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
			server.Protocols.SetHTTP1(true)
		} else {
			server.Protocols.SetHTTP1(true)
			server.Protocols.SetHTTP2(true)
			server.Protocols.SetUnencryptedHTTP2(true)
		}

		shutdownComplete := make(chan struct{})
		go func() {
			<-stopContext.Done()
			mainLogger.Info("Shutting down...")
			shutdownContext, cl := context.WithTimeout(context.Background(), args.shutdownTimeout)
			defer cl()
			server.Shutdown(shutdownContext)
			close(shutdownComplete)
		}()

		// setup done
		if err := server.Serve(listener); err == http.ErrServerClosed {
			// need to wait shutdown to exit
			<-shutdownComplete
			mainLogger.Info("Reached normal server termination.")
		} else {
			mainLogger.Critical("Server terminated with a reason: %v", err)
		}
		return 0
	case proxyModeSOCKS5:
		opts := []socks5.Option{
			socks5.WithLogger(socks5.NewLogger(log.New(logWriter, "SOCKSSRV: ", log.LstdFlags|log.Lshortfile))),
			socks5.WithRule(
				&socks5.PermitCommand{
					EnableConnect: true,
				},
			),
			socks5.WithConnectHandle(
				handler.SOCKSHandler(
					dialerRoot,
					proxyLogger,
					forwarder,
				),
			),
		}
		switch cs := authProvider.(type) {
		case auth.NoAuth:
			// pass, authentication is not needed
		case socks5.CredentialStore:
			opts = append(opts, socks5.WithCredential(cs))
		default:
			mainLogger.Critical("Chosen authentication method is not supported by this proxy operation mode.")
			return 2
		}

		go func() {
			<-stopContext.Done()
			mainLogger.Info("Shutting down...")
			listener.Close()
		}()
		server := socks5.NewServer(opts...)
		if err := server.Serve(listener); err != nil {
			mainLogger.Info("Reached normal server termination.")
		}
		return 0
	}

	mainLogger.Critical("unknown proxy mode")
	return 2
}

func makeServerTLSConfig(args *CLIArgs) (*tls.Config, error) {
	cfg := tls.Config{
		MinVersion: uint16(args.minTLSVersion),
		MaxVersion: uint16(args.maxTLSVersion),
	}
	if args.cert != "" {
		cert, err := tls.LoadX509KeyPair(args.cert, args.key)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	if args.cafile != "" {
		roots, err := tlsutil.LoadCAfile(args.cafile)
		if err != nil {
			return nil, err
		}
		cfg.ClientCAs = roots
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
	}
	var err error
	cfg.CipherSuites, err = tlsutil.ParseCipherList(args.ciphers)
	if err != nil {
		return nil, err
	}
	cfg.CurvePreferences, err = tlsutil.ParseCurveList(args.curves)
	if err != nil {
		return nil, err
	}
	if args.tlsALPNEnabled {
		if len(args.tlsALPNProtos.values) == 0 {
			if !args.disableHTTP2 {
				cfg.NextProtos = []string{"h2", "http/1.1"}
			} else {
				cfg.NextProtos = []string{"http/1.1"}
			}
		} else {
			cfg.NextProtos = args.tlsALPNProtos.values
		}
	}
	return &cfg, nil
}

func list_ciphers() {
	for _, cipher := range tls.CipherSuites() {
		fmt.Println(cipher.Name)
	}
}

func list_curves() {
	for _, curve := range tlsutil.Curves() {
		fmt.Println(curve.String())
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

func readConfig(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("unable to open config file %q: %w", filename, err)
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.Comma = ' '
	r.Comment = '#'
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	r.ReuseRecord = true
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("configuration file parsing failed: %w", err)
		}
		switch len(record) {
		case 0:
			continue
		case 1:
			if err := flag.Set(record[0], "true"); err != nil {
				line, _ := r.FieldPos(0)
				return fmt.Errorf("error parsing config file %q at line %d (%#v): %w", filename, line, record, err)
			}
		case 2:
			if err := flag.Set(record[0], record[1]); err != nil {
				line, _ := r.FieldPos(0)
				return fmt.Errorf("error parsing config file %q at line %d (%#v): %w", filename, line, record, err)
			}
		default:
			unified := strings.Join(record[1:], " ")
			if err := flag.Set(record[0], unified); err != nil {
				line, _ := r.FieldPos(0)
				return fmt.Errorf("error parsing config file %q at line %d (%#v): %w", filename, line, record, err)
			}
		}
	}
	return nil
}

func main() {
	os.Exit(run())
}
