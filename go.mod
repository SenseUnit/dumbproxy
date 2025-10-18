module github.com/SenseUnit/dumbproxy

go 1.24.0

toolchain go1.24.6

require (
	github.com/Snawoot/uniqueslice v0.1.1
	github.com/coreos/go-systemd/v22 v22.6.0
	github.com/dop251/goja v0.0.0-20251008123653-cf18d89f3cf6
	github.com/hashicorp/go-multierror v1.1.1
	github.com/jellydator/ttlcache/v3 v3.4.0
	github.com/libp2p/go-reuseport v0.4.0
	github.com/ncruces/go-dns v1.2.7
	github.com/redis/go-redis/v9 v9.14.0
	github.com/refraction-networking/utls v1.8.1
	github.com/tg123/go-htpasswd v1.2.4
	github.com/things-go/go-socks5 v0.1.0
	github.com/zeebo/xxh3 v1.0.2
	golang.org/x/crypto v0.43.0
	golang.org/x/crypto/x509roots/fallback v0.0.0-20251009181029-0b7aa0cfb07b
	golang.org/x/net v0.46.0
	golang.org/x/sync v0.17.0
	golang.org/x/time v0.14.0
)

require (
	github.com/GehirnInc/crypt v0.0.0-20230320061759-8cc1b52080c5 // indirect
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/dlclark/regexp2 v1.11.5 // indirect
	github.com/go-sourcemap/sourcemap v2.1.4+incompatible // indirect
	github.com/google/pprof v0.0.0-20251007162407-5df77e3f7d1d // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/pires/go-proxyproto v0.8.1
	golang.org/x/sys v0.37.0 // indirect
	golang.org/x/term v0.36.0 // indirect
	golang.org/x/text v0.30.0 // indirect
)

replace golang.org/x/time => github.com/Snawoot/xtime v0.0.0-20250501122004-d1ce456948bb
