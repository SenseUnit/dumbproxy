module github.com/SenseUnit/dumbproxy

go 1.24

toolchain go1.24.2

require (
	github.com/Snawoot/uniqueslice v0.1.1
	github.com/coreos/go-systemd/v22 v22.5.0
	github.com/dop251/goja v0.0.0-20250309171923-bcd7cc6bf64c
	github.com/hashicorp/go-multierror v1.1.1
	github.com/jellydator/ttlcache/v3 v3.3.0
	github.com/libp2p/go-reuseport v0.4.0
	github.com/redis/go-redis/v9 v9.8.0
	github.com/tg123/go-htpasswd v1.2.4
	github.com/zeebo/xxh3 v1.0.2
	golang.org/x/crypto v0.38.0
	golang.org/x/crypto/x509roots/fallback v0.0.0-20250512154111-9f6bf8449a9f
	golang.org/x/net v0.40.0
	golang.org/x/sync v0.14.0
	golang.org/x/time v0.11.0
)

require (
	github.com/GehirnInc/crypt v0.0.0-20230320061759-8cc1b52080c5 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/dlclark/regexp2 v1.11.5 // indirect
	github.com/go-sourcemap/sourcemap v2.1.4+incompatible // indirect
	github.com/google/pprof v0.0.0-20250501235452-c0086092b71a // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.10 // indirect
	github.com/pires/go-proxyproto v0.8.1
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/term v0.32.0 // indirect
	golang.org/x/text v0.25.0 // indirect
)

replace golang.org/x/time => github.com/Snawoot/xtime v0.0.0-20250501122004-d1ce456948bb
