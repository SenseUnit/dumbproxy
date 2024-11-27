dumbproxy
=========

[![dumbproxy](https://snapcraft.io//dumbproxy/badge.svg)](https://snapcraft.io/dumbproxy)

Dumbest HTTP proxy ever.

## Features

* Cross-platform (Windows/Mac OS/Linux/Android (via shell)/\*BSD)
* Deployment with a single self-contained binary
* Zero-configuration
* Supports CONNECT method and forwarding of HTTPS connections
* Supports `Basic` proxy authentication
* Supports TLS operation mode (HTTP(S) proxy over TLS)
* Native ACME support (can issue TLS certificates automatically using Let's Encrypt or BuyPass)
* Supports client authentication with client TLS certificates
* Supports HTTP/2
* Resilient to DPI (including active probing, see `hidden_domain` option for authentication providers)
* Connecting via upstream HTTP(S)/SOCKS5 proxies (proxy chaining)
* systemd socket activation

## Installation

#### Binary download

Pre-built binaries available on [releases](https://github.com/SenseUnit/dumbproxy/releases/latest) page.

#### From source

Alternatively, you may install dumbproxy from source. Run within source directory

```
go install
```

#### Docker

Docker image is available as well. Here is an example for running proxy as a background service:

```sh
docker run -d \
    --security-opt no-new-privileges \
    -p 8080:8080 \
    --restart unless-stopped \
    --name dumbproxy \
    ghcr.io/senseunit/dumbproxy -auth 'static://?username=admin&password=123456'
```

#### Snap Store

[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-black.svg)](https://snapcraft.io/dumbproxy)

```bash
sudo snap install dumbproxy
```

## Usage

Just run program and it'll start accepting connections on port 8080 (default).

### Example: plain proxy

Run proxy on port 1234 with `Basic` authentication with username `admin` and password `123456`:

```sh
dumbproxy -bind-address :1234 -auth 'static://?username=admin&password=123456'
```

### Example: HTTP proxy over TLS (LetsEncrypt automatic certs)

Run HTTPS proxy (HTTP proxy over TLS) with automatic certs from LetsEncrypt on port 443 with `Basic` authentication with username `admin` and password `123456`:

```sh
dumbproxy -bind-address :443 -auth 'static://?username=admin&password=123456' -autocert
```

### Example: HTTP proxy over TLS (BuyPass automatic certs)

Run HTTPS proxy (HTTP proxy over TLS) with automatic certs from BuyPass on port 443 with `Basic` authentication with username `admin` and password `123456`:

```sh
dumbproxy \
	-bind-address :443 \
	-auth 'static://?username=admin&password=123456' \
	-autocert \
	-autocert-acme 'https://api.buypass.com/acme/directory' \
	-autocert-email YOUR-EMAIL@EXAMPLE.ORG \
	-autocert-http :80
```

## Using HTTP-over-TLS proxy

It's quite trivial to set up program which supports proxies to use dumbproxy in plain HTTP mode. However, using HTTP proxy over TLS connection with browsers is little bit tricky. Note that TLS must be enabled (`-cert` and `-key` options or `-autocert` option) for this to work.

### Routing all browsers on Windows via HTTPS proxy

Open proxy settings in system's network settings:

![win10-proxy-settings](https://user-images.githubusercontent.com/3524671/83258553-216f7700-a1bf-11ea-8af9-3d8aed5b2e71.png)

Turn on setup script option and set script address:

```
data:,function FindProxyForURL(u, h){return "HTTPS example.com:8080";}
```

where instead of `example.com:8080` you should use actual address of your HTTPS proxy.

Note: this method will not work with MS Edge Legacy.

### Using with Firefox

#### Option 1. Inline PAC file in settings.

Open Firefox proxy settings, switch proxy mode to "Automatic proxy configuration URL". Specify URL:

```
data:,function FindProxyForURL(u, h){return "HTTPS example.com:8080";}
```

![ff_https_proxy](https://user-images.githubusercontent.com/3524671/82768442-afea9e00-9e37-11ea-80fd-1eccf55b89fa.png)

#### Option 2. Browser extension.

Use any proxy switching browser extension which supports HTTPS proxies like [this one](https://addons.mozilla.org/ru/firefox/addon/switchyomega/).

### Using with Chrome

#### Option 1. CLI option.

Specify proxy via command line:

```
chromium-browser --proxy-server='https://example.com:8080'
```

#### Option 2. Browser extension.

Use any proxy switching browser extension which supports HTTPS proxies like [this one](https://chrome.google.com/webstore/detail/proxy-switchyomega/padekgcemlokbadohgkifijomclgjgif).

### Using with other applications

It is possible to expose remote HTTPS proxy as a local plaintext HTTP proxy with help of external application which performs remote communication via TLS and exposes local plaintext socket. [steady-tun](https://github.com/Snawoot/steady-tun) appears to be most suitable for this because it supports connection pooling to hide connection delay.

### Using with Android

1. Run proxy as in [examples](#usage) above.
2. Install Adguard on your Android: [Guide](https://adguard.com/en/adguard-android/overview.html).
3. Follow [this guide](https://adguard.com/en/blog/configure-proxy.html#configuringproxyinadguardforandroid), skipping server configuration. Use proxy type HTTPS if you set up TLS-enabled server or else use HTTP type.
4. Enjoy!

## Authentication

Authentication parameters are passed as URI via `-auth` parameter. Scheme of URI defines authentication metnod and query parameters define parameter values for authentication provider.

* `none` - no authentication. Example: `none://`. This is default.
* `static` - basic authentication for single login and password pair. Example: `static://?username=admin&password=123456`. Parameters:
  * `username` - login.
  * `password` - password.
  * `hidden_domain` - if specified and is not an empty string, proxy will respond with "407 Proxy Authentication Required" only on specified domain. All unauthenticated clients will receive "400 Bad Request" status. This option is useful to prevent DPI active probing from discovering that service is a proxy, hiding proxy authentication prompt when no valid auth header was provided. Hidden domain is used for generating 407 response code to trigger browser authorization request in cases when browser has no prior knowledge proxy authentication is required. In such cases user has to navigate to any hidden domain page via plaintext HTTP, authenticate themselves and then browser will remember authentication.
* `basicfile` - use htpasswd-like file with login and password pairs for authentication. Such file can be created/updated with command like this: `dumbproxy -passwd /etc/dumbproxy.htpasswd username password` or with `htpasswd` utility from Apache HTTPD utils. `path` parameter in URL for this provider must point to a local file with login and bcrypt-hashed password lines. Example: `basicfile://?path=/etc/dumbproxy.htpasswd`.
  * `path` - location of file with login and password pairs. File format is similar to htpasswd files. Each line must be in form `<username>:<bcrypt hash of password>`. Empty lines and lines starting with `#` are ignored.
  * `hidden_domain` - same as in `static` provider
  * `reload` - interval for conditional password file reload, if it was modified since last load. Use negative duration to disable autoreload. Default: `15s`.
* `hmac` - authentication with HMAC-signatures passed as username and password via basic authentication scheme. In that scheme username represents user login as usual and password should be constructed as follows: *password := urlsafe\_base64\_without\_padding(expire\_timestamp || hmac\_sha256(secret, "dumbproxy grant token v1" || username || expire\_timestamp))*, where *expire_timestamp* is 64-bit big-endian UNIX timestamp and *||* is a concatenation operator. [This Python script](https://gist.github.com/Snawoot/2b5acc232680d830f0f308f14e540f1d) can be used as a reference implementation of signing. Dumbproxy itself also provides built-in signer: `dumbproxy -hmac-sign <HMAC key> <username> <validity duration>`.
  * `secret` - hex-encoded HMAC secret key. Alternatively it can be specified by `DUMBPROXY_HMAC_SECRET` environment variable. Secret key can be generated with command like this: `openssl rand -hex 32` or `dumbproxy -hmac-genkey`.
  * `hidden_domain` - same as in `static` provider
* `cert` - use mutual TLS authentication with client certificates. In order to use this auth provider server must listen sockert in TLS mode (`-cert` and `-key` options) and client CA file must be specified (`-cacert`). Example: `cert://`.
  * `blacklist` - location of file with list of serial numbers of blocked certificates, one per each line in form of hex-encoded colon-separated bytes. Example: `ab:01:02:03`. Empty lines and comments starting with `#` are ignored.
  * `reload` - interval for certificate blacklist file reload, if it was modified since last load. Use negative duration to disable autoreload. Default: `15s`.

## Synopsis

```
$ ~/go/bin/dumbproxy -h
Usage of /home/user/go/bin/dumbproxy:
  -auth string
    	auth parameters (default "none://")
  -autocert
    	issue TLS certificates automatically
  -autocert-acme string
    	custom ACME endpoint (default "https://acme-v02.api.letsencrypt.org/directory")
  -autocert-dir string
    	path to autocert cache (default "/home/user/.dumbproxy/autocert")
  -autocert-email string
    	email used for ACME registration
  -autocert-http string
    	listen address for HTTP-01 challenges handler of ACME
  -autocert-whitelist value
    	restrict autocert domains to this comma-separated list
  -bind-address string
    	HTTP proxy listen address. Set empty value to use systemd socket activation. (default ":8080")
  -cafile string
    	CA file to authenticate clients with certificates
  -cert string
    	enable TLS and use certificate
  -ciphers string
    	colon-separated list of enabled ciphers
  -disable-http2
    	disable HTTP2
  -hmac-genkey
    	generate hex-encoded HMAC signing key of optimal length
  -hmac-sign
    	sign username with specified key for given validity period. Positional arguments are: hex-encoded HMAC key, username, validity duration.
  -ip-hints string
    	a comma-separated list of source addresses to use on dial attempts. "$lAddr" gets expanded to local address of connection. Example: "10.0.0.1,fe80::2,$lAddr,0.0.0.0,::"
  -key string
    	key for TLS certificate
  -list-ciphers
    	list ciphersuites
  -max-tls-version value
    	maximum TLS version accepted by server (default TLS13)
  -min-tls-version value
    	minimal TLS version accepted by server (default TLS12)
  -passwd string
    	update given htpasswd file and add/set password for username. Username and password can be passed as positional arguments or requested interactively
  -passwd-cost int
    	bcrypt password cost (for -passwd mode) (default 4)
  -proxy value
    	upstream proxy URL. Can be repeated multiple times to chain proxies. Examples: socks5h://127.0.0.1:9050; https://user:password@example.com:443
  -timeout duration
    	timeout for network operations (default 10s)
  -user-ip-hints
    	allow IP hints to be specified by user in X-Src-IP-Hints header
  -verbosity int
    	logging verbosity (10 - debug, 20 - info, 30 - warning, 40 - error, 50 - critical) (default 20)
  -version
    	show program version and exit
```

## See Also

* [Project Wiki](https://github.com/SenseUnit/dumbproxy/wiki)
* [Community in Telegram](https://t.me/alternative_proxy)
