dumbproxy
=========

[![dumbproxy](https://snapcraft.io//dumbproxy/badge.svg)](https://snapcraft.io/dumbproxy)

Simple, scriptable, secure HTTP/SOCKS5 forward proxy.

## Features

* Multiple protocol support: both HTTP and SOCKS5 are supported
* Cross-platform (Windows/Mac OS/Linux/Android (via shell)/\*BSD)
* Deployment with a single self-contained binary
* Zero-configuration
* Seamless forwarding of all kinds of TCP connections in addition to regular web-traffic forwarding
* Supports `Basic` proxy authentication
  * Via auto-reloaded NCSA httpd-style passwords file
  * Via static login and password
  * Via HMAC signatures provisioned by central authority (e.g. some webservice)
  * Via Redis or Redis Cluster database
* Supports TLS operation mode (HTTP(S) proxy over TLS)
  * Supports client authentication with client TLS certificates
  * Native ACME support (can issue TLS certificates automatically using Let's Encrypt or BuyPass)
    * Certificate cache in local directory
    * Certificate cache in Redis/Redis Cluster
    * Optional local in-memory inner cache
    * Optional AEAD encryption layer for cache
* Per-user bandwidth limits
* HTTP/2 support, both server and client, including h2c support
* Advanced DNS support
  * Plain DNS
  * DNS-over-HTTPS
  * DNS-over-TLS
  * System-provided DNS
  * Competitive parallel resolving using any of above
  * Optional DNS cache
* Resilient to DPI (including active probing, see `hidden_domain` option for authentication providers)
* Connecting via upstream HTTP(S)/SOCKS5 proxies (proxy chaining)
  * Optional parroting of TLS fingerprints of popular software such as web browsers.
  * Optional countermeasures against TLS-in-TLS detection (available when both client and server are dumbproxy).
* systemd socket activation
* [Proxy protocol](https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt) support for working behind a reverse proxy (HAProxy, Nginx)
* Scripting with JavaScript:
  * Access filter by JS function
  * Upstream proxy selection by JS function
* Seamless proxy client integration with OpenSSH: `ssh -o ProxyCommand="dumbproxy -config proxy.cfg -mode stdio %h %p" root@server1`

## Installation

#### Binary download

Pre-built binaries available on [releases](https://github.com/SenseUnit/dumbproxy/releases/latest) page.

#### From source

Alternatively, you may install dumbproxy from source. Run within source directory

```
go install .
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

### Example: HTTP proxy over TLS (pre-issued cert) behind Nginx reverse proxy performing SNI routing

Run HTTPS proxy (HTTP proxy over TLS) with pre-issued cert listening proxy protocol on localhost's 10443 with `Basic` authentication (users and passwords in /etc/dumbproxy.htpasswd)):

```sh
dumbproxy \
	-bind-address 127.0.0.1:10443 \
	-proxyproto \
	-auth basicfile://?path=/etc/dumbproxy.htpasswd \
	-cert=/etc/letsencrypt/live/proxy.example.com/fullchain.pem \
	-key=/etc/letsencrypt/live/proxy.example.com/privkey.pem
```

Nginx config snippet:

```
stream
{
	ssl_preread on;

	map $ssl_preread_server_name $backend
	{
		proxy.example.com dumbproxy;
		...
	}

	upstream dumbproxy
	{
		server 127.0.0.1:10443;
	}

	server
	{
		listen 443;
		listen [::]:443;
		proxy_protocol on;
		proxy_pass $backend;
	}

}
```

### Example: HTTP proxy over TLS (ACME-issued cert) behind Traefik reverse proxy running in Docker Compose and performing SNI routing

Have following labels attached to dumbproxy service in compose file:

```yaml
        traefik.enable: "true"
        traefik.tcp.routers.dumbproxy.service: dumbproxy
        traefik.tcp.routers.dumbproxy.rule: HostSNI(`<your-domain>`)
        traefik.tcp.routers.dumbproxy.tls: "true"
        traefik.tcp.routers.dumbproxy.tls.passthrough: "false"
        traefik.tcp.routers.dumbproxy.tls.certResolver: letsencrypt
        traefik.tcp.services.dumbproxy.loadBalancer.server.port: 8080
        traefik.tcp.services.dumbproxy.loadbalancer.proxyProtocol.version: 2
```

dumbproxy service should be run in plaintext mode as TLS is handled on Traefik side. So options would be just `-bind-address=:8080 -proxyproto` and probably something for authorization. This recipe is explained in [Wiki](https://github.com/SenseUnit/dumbproxy/wiki/Docker-Compose-Deployment-behind-Traefik-Reverse-Proxy) with more details and configuration files provided for context.

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

See [Wiki](https://github.com/SenseUnit/dumbproxy/wiki) for more examples, recipes and notes.

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

![ff\_https\_proxy](https://user-images.githubusercontent.com/3524671/82768442-afea9e00-9e37-11ea-80fd-1eccf55b89fa.png)

#### Option 2. Browser extension.

Use any proxy switching browser extension which supports HTTPS proxies like [this one](https://addons.mozilla.org/en-US/firefox/addon/zeroomega/).

### Using with Chrome

#### Option 1. CLI option.

Specify proxy via command line:

```
chromium-browser --proxy-server='https://example.com:8080'
```

#### Option 2. Browser extension.

Use any proxy switching browser extension which supports HTTPS proxies like [this one](https://chromewebstore.google.com/detail/proxy-switchyomega-3-zero/pfnededegaaopdmhkdmcofjmoldfiped).

### Using with other applications

It is possible to expose remote HTTPS proxy as a local plaintext HTTP proxy with the help of some application which performs remote communication via TLS and exposes local plaintext socket. dumbproxy itself can play this role and use upstream proxy to provide local proxy service. For example, command

```
dumbproxy -bind-address 127.0.0.1:8080 -proxy 'https://login:password@example.org'
```

would expose remote HTTPS proxy at example.org:443 with `login` and `password` on local port 8080 as a regular HTTP proxy without authentication. Or, if you prefer mTLS authentication, it would be

```
dumbproxy -bind-address 127.0.0.1:8080 -proxy 'https://example.org?cert=cert.pem&key=key.pem&cafile=ca.pem'
```

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
* `basicfile` - use htpasswd-like file with login and password pairs for authentication. Such file can be created/updated with command like this: `dumbproxy -passwd /etc/dumbproxy.htpasswd username password` or with `htpasswd` utility from Apache HTTPD utils. `path` parameter in URL for this provider must point to a local file with login and bcrypt-hashed password lines. Example: `basicfile://?path=/etc/dumbproxy.htpasswd`. Parameters:
  * `path` - location of file with login and password pairs. File format is similar to htpasswd files. Each line must be in form `<username>:<bcrypt hash of password>`. Empty lines and lines starting with `#` are ignored.
  * `hidden_domain` - same as in `static` provider.
  * `reload` - interval for conditional password file reload, if it was modified since last load. Use negative duration to disable autoreload. Default: `15s`.
* `hmac` - authentication with HMAC-signatures passed as username and password via basic authentication scheme. In that scheme username represents user login as usual and password should be constructed as follows: *password := urlsafe\_base64\_without\_padding(expire\_timestamp || hmac\_sha256(secret, "dumbproxy grant token v1" || username || expire\_timestamp))*, where *expire_timestamp* is 64-bit big-endian UNIX timestamp and *||* is a concatenation operator. [This Python script](https://gist.github.com/Snawoot/2b5acc232680d830f0f308f14e540f1d) can be used as a reference implementation of signing. Dumbproxy itself also provides built-in signer: `dumbproxy -hmac-sign <HMAC key> <username> <validity duration>`. Parameters of this auth scheme are:
  * `secret` - hex-encoded HMAC secret key. Alternatively it can be specified by `DUMBPROXY_HMAC_SECRET` environment variable. Secret key can be generated with command like this: `openssl rand -hex 32` or `dumbproxy -hmac-genkey`.
  * `hidden_domain` - same as in `static` provider.
* `cert` - use mutual TLS authentication with client certificates. In order to use this auth provider server must listen sockert in TLS mode (`-cert` and `-key` options) and client CA file must be specified (`-cacert`). Example: `cert://`. Parameters of this scheme are:
  * `blacklist` - location of file with list of serial numbers of blocked certificates, one per each line in form of hex-encoded colon-separated bytes. Example: `ab:01:02:03`. Empty lines and comments starting with `#` are ignored.
  * `reload` - interval for certificate blacklist file reload, if it was modified since last load. Use negative duration to disable autoreload. Default: `15s`.
* `redis` - use external Redis database to lookup password verifiers for users. The password format is similar to `basicfile` mode or `htpasswd` encoding except username goes into Redis key name, colon is skipped and the rest goes to value of this key. For example, login-password pair `test` / `123456` can be encoded as Redis key `test` with value `$2y$05$zs1EJayCIyYtG.NQVzu9SeNvMP0XYWa42fQv.XNDx33wwbg98SnUq`. Example of auth parameter: `-auth 'redis://?url=redis%3A//default%3A123456Y%40redis-14623.c531.europe-west3-1.gce.redns.redis-cloud.com%3A17954/0&key_prefix=auth_'`. Parameters:
  * `url` - URL specifying Redis instance to connect to. See [ParseURL](https://pkg.go.dev/github.com/redis/go-redis/v9#ParseURL) documentation for the complete specification of Redis URL format.
  * `key_prefix` - prefix to prepend to each key before lookup. Helps isolate keys under common prefix. Default is empty string (`""`).
  * `hidden_domain` - same as in `static` provider.
* `redis-cluster` - same as Redis, but uses Redis Cluster client instead.
  * `url` - URL specifying Redis instance to connect to. See [ParseClusterURL](https://pkg.go.dev/github.com/redis/go-redis/v9#ParseClusterURL) documentation for the complete specification of Redis URL format.
  * `key_prefix` - prefix to prepend to each key before lookup. Helps isolate keys under common prefix. Default is empty string (`""`).
  * `hidden_domain` - same as in `static` provider.

## Scripting

With the dumbproxy, it is possible to modify request processing behaviour using simple scripts written in the JavaScript programming language.

### Access filter by JS script

It is possible to filter (allow or deny) requests with simple `access` JS function. Such function can be loaded with the `-js-access-filter` option. Option value must specify location of script file where `access` function is defined.

`access` function is invoked with following parameters:

1. **Request** *(Object)*. It contains following properties:
   * **method** *(String)* - HTTP method used in request (CONNECT, GET, POST, PUT, etc.).
   * **url** *(String)* - URL parsed from the URI supplied on the Request-Line.
   * **proto** *(String)* - the protocol version for incoming server requests.
   * **protoMajor** *(Number)* - numeric major protocol version.
   * **protoMinor** *(Number)* - numeric minor protocol version.
   * **header** *(Object)* - mapping of *String* headers (except Host) in canonical form to an *Array* of their *String* values.
   * **contentLength** *(Number)* - length of request body, if known.
   * **transferEncoding** *(Array)* - lists the request's transfer encodings from outermost to innermost.
   * **host** *(String)* - specifies the host on which the URL is sought. For HTTP/1 (per RFC 7230, section 5.4), this is either the value of the "Host" header or the host name given in the URL itself. For HTTP/2, it is the value of the ":authority" pseudo-header field.
   * **remoteAddr** *(String)* - client's IP:port.
   * **requestURI** *(String)* - the unmodified request-target of the Request-Line (RFC 7230, Section 3.1.1) as sent by the client to a server.
2. **Destination address** *(Object)*. It's an address where actual connection is about to be created. It contains following properties:
   * **network** *(String)* - connection type. Should be `"tcp"` in most cases unless restricted to specific address family (`"tcp4"` or `"tcp6"`).
   * **originalHost** *(String)* - original hostname or IP address parsed from request.
   * **resolvedHost** *(String)* - resolved hostname from request or `null` if resolving was not performed (e.g. if upstream dialer is a proxy).
   * **port** *(Number)* - port number.
3. **Username** *(String)*. Name of the authenticated user or an empty string if there is no authentication.

`access` function must return boolean value, `true` allows request and `false` forbids it. Any exception will be reported to log and the corresponding request will be denied.

Also it is possible to use builtin `print` function to print arbitrary values into dumbproxy log for debugging purposes.

Example:

```js
// Deny unsafe ports for HTTP and non-SSL ports for HTTPS.

const SSL_ports = [
	443,
]
const Safe_ports = [
	80,                // http
	21,                // ftp
	443,               // https
	70,                // gopher
	210,               // wais
	280,               // http-mgmt
	488,               // gss-http
	591,               // filemaker
	777,               // multiling http
]
const highPortBase = 1025

function access(req, dst, username) {
	if (req.method == "CONNECT") {
		if (SSL_ports.includes(dst.port)) return true
	} else {
		if (dst.port >= highPortBase || Safe_ports.includes(dst.port)) return true
	}
	return false
}
```

### Upstream proxy selection by JS script

dumbproxy can select upstream proxy dynamically invoking `getProxy` JS function from file specified by `-js-proxy-router` option.

Note that this option can be repeated multiple times, same as `-proxy` option for chaining of proxies. These two options can be used together and order of chaining will be as they come in command line. For generalization purposes we can say that `-proxy` option is equivalent to `-js-proxy-router` option with script which returns just one static proxy.

`getProxy` function is invoked with the [same parameters](#access-filter-by-js-script) as the `access` function. But unlike `access` function it is expected to return proxy URL in string format *scheme://[user:password@]host:port* or empty string `""` if no additional upstream proxy needed (i.e. direct connection if there are no other proxy dialers defined in chain). See [supported upstream proxy schemes](#supported-upstream-proxy-schemes) for details.

Example:

```js
// Redirect .onion hidden domains to Tor SOCKS5 proxy

function getProxy(req, dst, username) {
	if (dst.originalHost.replace(/\.$/, "").toLowerCase().endsWith(".onion")) {
		return "socks5://127.0.0.1:9050"
	}
	return ""
}
```

> [!NOTE]  
> `getProxy` can be invoked once or twice per request. If first invocation with `null` resolved host address returns "direct" mode and no other dialer has suppressed name resolving, name resolution will be performed and `getProxy` will be invoked once again with resolved address for the final decision.
> 
> This shouldn't be much of concern, though, if `getProxy` function doesn't use dst.resolvedHost and returns consistent values across invocations with the rest of inputs having same values.

## Supported upstream proxy schemes

Supported proxy schemes are:

* `http` - regular HTTP proxy with the CONNECT method support. Examples: `http://example.org:3128`.
* `https` - HTTP proxy over TLS connection. Examples: `https://user:password@example.org`, `https://example.org?cert=cert.pem&key=key.pem`. This method also supports additional parameters passed in query string:
  * `cafile` - file with CA certificates in PEM format used to verify TLS peer.
  * `sni` - override value of ServerName Indication extension.
  * `peername` - expect specified name in peer certificate. Empty string relaxes any name constraints.
  * `cert` - file with user certificate for mutual TLS authentication. Should be used in conjunction with `key`.
  * `key` - file with private key matching user certificate specified with `cert` option.
  * `ciphers` - colon-separated list of enabled TLS ciphersuites.
  * `curves` - colon-separated list of enabled TLS key exchange curves.
  * `min-tls-version` - minimum TLS version.
  * `max-tls-version` - maximum TLS version.
  * `utls-fp` - TLS fingerprint parroting with uTLS library. See the [list](https://pkg.go.dev/github.com/refraction-networking/utls#pkg-variables) of allowed client IDs. Example: `utls-fp=HelloChrome_Auto`.
* `http+optimistic` - (EXPERIMENTAL) HTTP proxy dialer which reads the connection success response asynchronously.
* `https+optimistic` - (EXPERIMENTAL) HTTP proxy over TLS dialer which reads the connection success response asynchronously. Options are same as for `https` dialer.
* `h2` - HTTP/2 proxy over TLS connection. Examples: `h2://user:password@example.org`, `h2://example.org?cert=cert.pem&key=key.pem`. This method also supports additional parameters passed in query string:
  * `cafile` - file with CA certificates in PEM format used to verify TLS peer.
  * `sni` - override value of ServerName Indication extension.
  * `peername` - expect specified name in peer certificate. Empty string relaxes any name constraints.
  * `cert` - file with user certificate for mutual TLS authentication. Should be used in conjunction with `key`.
  * `key` - file with private key matching user certificate specified with `cert` option.
  * `ciphers` - colon-separated list of enabled TLS ciphersuites.
  * `curves` - colon-separated list of enabled TLS key exchange curves.
  * `min-tls-version` - minimum TLS version.
  * `max-tls-version` - maximum TLS version.
  * `fetchrandom` - request server to send random data in the first request via every new HTTP/2 connection. Useful to trick TLS-in-TLS detection. Value format: length as a number or range `x-y`. Example: `fetchrandom=100000-500000`.
  * `utls-fp` - TLS fingerprint parroting with uTLS library. See the [list](https://pkg.go.dev/github.com/refraction-networking/utls#pkg-variables) of allowed client IDs. Example: `utls-fp=HelloChrome_Auto`.
* `h2c` - HTTP/2 proxy over plaintext connection with the CONNECT method support. Examples: `h2c://example.org:8080`.
  * `fetchrandom` - request server to send random data in the first request via every new HTTP/2 connection. Useful to trick TLS-in-TLS detection. Value format: length as a number or range `x-y`. Example: `fetchrandom=100000-500000`.
* `socks5`, `socks5h` - SOCKS5 proxy with hostname resolving via remote proxy. Example: `socks5://127.0.0.1:9050`.
* `socks5s`, `socks5hs` - SOCKS5 proxy over TLS with hostname resolving via remote proxy. Example: `socks5s://example.com:10443`. This method also supports additional parameters passed in query string:
  * `cafile` - file with CA certificates in PEM format used to verify TLS peer.
  * `sni` - override value of ServerName Indication extension.
  * `peername` - expect specified name in peer certificate. Empty string relaxes any name constraints.
  * `cert` - file with user certificate for mutual TLS authentication. Should be used in conjunction with `key`.
  * `key` - file with private key matching user certificate specified with `cert` option.
  * `ciphers` - colon-separated list of enabled TLS ciphersuites.
  * `curves` - colon-separated list of enabled TLS key exchange curves.
  * `min-tls-version` - minimum TLS version.
  * `max-tls-version` - maximum TLS version.
  * `utls-fp` - TLS fingerprint parroting with uTLS library. See the [list](https://pkg.go.dev/github.com/refraction-networking/utls#pkg-variables) of allowed client IDs. Example: `utls-fp=HelloChrome_Auto`.
* `set-src-hints` - not an actual proxy, but a signal to use different source IP address hints for this connection. It's useful to route traffic across multiple network interfaces, including VPN connections. URL has to have one query parameter `hints` with a comma-separated list of IP addresses. See `-ip-hints` command line option for more details. Example: `set-src-hints://?hints=10.2.0.2`
* `cached` - pseudo-dialer which caches construction of another dialer specified by URL passed in `url` parameter of query string. Useful for dialers which are constructed dynamically from JS router script and which load certificate files. Example: `cache://?url=https%3A%2F%2Fexample.org%3Fcert%3Dcert.pem%26key%3Dkey.pem&ttl=5m`. Query string parameters are:
   * `url` - actual proxy URL. Note that just like any query string parameter this one has to be URL-encoded to be passed as query string value.
   * `ttl` - time to live for cache record. Examples: `15s`, `2m`, `1h`.

## Configuration files

Reading options from configuration file is now supported too! For example, command from one of examples above:

```
dumbproxy \
    -bind-address 127.0.0.1:10443 \
    -proxyproto \
    -auth basicfile://?path=/etc/dumbproxy.htpasswd \
    -cert=/etc/letsencrypt/live/proxy.example.com/fullchain.pem \
    -key=/etc/letsencrypt/live/proxy.example.com/privkey.pem
```

becomes just

```
dumbproxy -config dp.cfg
```

having dp.cfg file with following content:

```
bind-address 127.0.0.1:10443
proxyproto
auth basicfile://?path=/etc/dumbproxy.htpasswd
cert /etc/letsencrypt/live/proxy.example.com/fullchain.pem
key /etc/letsencrypt/live/proxy.example.com/privkey.pem
```

Configuration format is [RFC 4180](https://www.rfc-editor.org/rfc/rfc4180.html) CSV with space character (`" "`) as a field separator instead of comma, `#` as a comment start character. Lines with only one field are treated as boolean flags, lines with two or more fields are treated as a key and its value, having extra fields joined with space.

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
  -autocert-cache-enc-key value
    	hex-encoded encryption key for cert cache entries. Can be also set with DUMBPROXY_CACHE_ENC_KEY environment variable
  -autocert-cache-redis value
    	use Redis URL for autocert cache
  -autocert-cache-redis-cluster value
    	use Redis Cluster URL for autocert cache
  -autocert-cache-redis-prefix string
    	prefix to use for keys in Redis or Redis Cluster cache
  -autocert-dir value
    	use directory path for autocert cache
  -autocert-email string
    	email used for ACME registration
  -autocert-http string
    	listen address for HTTP-01 challenges handler of ACME
  -autocert-local-cache-timeout duration
    	timeout for cert cache queries (default 10s)
  -autocert-local-cache-ttl duration
    	enables in-memory cache for certificates
  -autocert-whitelist value
    	restrict autocert domains to this comma-separated list
  -bind-address value
    	HTTP proxy listen address. Set empty value to use systemd socket activation. (default ":8080")
  -bind-pprof value
    	enables pprof debug endpoints
  -bind-pprof-unix-socket value
    	enables pprof debug endpoints listening on Unix domain socket
  -bind-reuseport
    	allow multiple server instances on the same port
  -bind-unix-socket value
    	Unix domain socket to listen to, overrides bind-address if set.
  -bw-limit uint
    	per-user bandwidth limit in bytes per second
  -bw-limit-buckets uint
    	number of buckets of bandwidth limit (default 1048576)
  -bw-limit-burst int
    	allowed burst size for bandwidth limit, how many "tokens" can fit into leaky bucket
  -bw-limit-separate
    	separate upload and download bandwidth limits
  -cafile string
    	CA file to authenticate clients with certificates
  -cert string
    	enable TLS and use certificate
  -ciphers string
    	colon-separated list of enabled ciphers
  -config value
    	read configuration from file with space-separated keys and values
  -curves string
    	colon-separated list of enabled key exchange curves
  -deny-dst-addr value
    	comma-separated list of CIDR prefixes of forbidden IP addresses (default 127.0.0.0/8, 0.0.0.0/32, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, ::1/128, ::/128, fe80::/10)
  -disable-http2
    	disable HTTP2
  -dns-cache-neg-ttl duration
    	TTL for negative responses of DNS cache (default 1s)
  -dns-cache-timeout duration
    	timeout for shared resolves of DNS cache (default 5s)
  -dns-cache-ttl duration
    	enable DNS cache with specified fixed TTL
  -dns-prefer-address value
    	address resolution preference (none/ipv4/ipv6) (default ipv4)
  -dns-server value
    	nameserver specification (udp://..., tcp://..., https://..., tls://..., doh://..., dot://..., default://). Option can be used multiple times for parallel use of multiple nameservers. Empty string resets the list
  -hmac-genkey
    	generate hex-encoded HMAC signing key of optimal length
  -hmac-sign
    	sign username with specified key for given validity period. Positional arguments are: hex-encoded HMAC key, username, validity duration.
  -ip-hints string
    	a comma-separated list of source addresses to use on dial attempts. "$lAddr" gets expanded to local address of connection. Example: "10.0.0.1,fe80::2,$lAddr,0.0.0.0,::"
  -js-access-filter string
    	path to JS script file with the "access" filter function
  -js-access-filter-instances int
    	number of JS VM instances to handle access filter requests (default 4)
  -js-proxy-router value
    	path to JS script file with the "getProxy" function
  -js-proxy-router-instances int
    	number of JS VM instances to handle proxy router requests (default 4)
  -key string
    	key for TLS certificate
  -list-ciphers
    	list ciphersuites
  -list-curves
    	list key exchange curves
  -max-tls-version value
    	maximum TLS version accepted by server (default TLS13)
  -min-tls-version value
    	minimum TLS version accepted by server (default TLS12)
  -mode value
    	proxy operation mode (http/socks5/stdio) (default http)
  -passwd string
    	update given htpasswd file and add/set password for username. Username and password can be passed as positional arguments or requested interactively
  -passwd-cost int
    	bcrypt password cost (for -passwd mode) (default 4)
  -proxy value
    	upstream proxy URL. Can be repeated multiple times to chain proxies. Examples: socks5h://127.0.0.1:9050; https://user:password@example.com:443
  -proxyproto
    	listen proxy protocol
  -req-header-timeout duration
    	amount of time allowed to read request headers (default 30s)
  -shutdown-timeout duration
    	grace period during server shutdown (default 1s)
  -tls-alpn-enabled
    	enable application protocol negotiation with TLS ALPN extension (default true)
  -unix-sock-mode value
    	set file mode for bound unix socket
  -unix-sock-unlink
    	delete file object located at Unix domain socket bind path before binding (default true)
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
