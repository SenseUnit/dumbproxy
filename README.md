dumbproxy
=========

Dumbiest HTTP proxy ever.

## Features

* Cross-platform (Windows/Mac OS/Linux/Android (via shell)/\*BSD)
* Zero-configuration
* Supports CONNECT method and forwarding of HTTPS connections
* Supports `Basic` proxy authentication
* Supports TLS operation mode (HTTP(S) proxy over TLS)

## Installation

#### Binary download

Pre-built binaries available on [releases](https://github.com/Snawoot/dumbproxy/releases/latest) page.

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
    yarmak/dumbproxy
```

#### Snap Store

[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-black.svg)](https://snapcraft.io/dumbproxy)

```bash
sudo snap install dumbproxy
```

## Usage

Just run program and it'll start accepting connections on port 8080 (default).

Example: run proxy on port 1234 with `Basic` authentication with username `admin` and password `123456`:

```sh
dumbproxy -bind-address :1234 -auth 'static://?username=admin&password=123456'
```

## Authentication

Authentication parameters are passed as URI via `-auth` parameter. Scheme of URI defines authentication metnod and query parameters define parameter values for authentication provider.

* `none` - no authentication. Example: `none://`. This is default.
* `static` - basic authentication for single login and password pair. Example: `static://?username=admin&password=123456`. Parameters:
  * `username` - login
  * `password` - password

## Synopsis

```
$ ~/go/bin/dumbproxy -h
  -auth string
    	auth parameters (default "none://")
  -bind-address string
    	HTTP proxy listen address (default ":8080")
  -cert string
    	enable TLS and use certificate
  -key string
    	key for TLS certificate
  -timeout duration
    	timeout for network operations (default 10s)
  -verbosity int
    	logging verbosity (10 - debug, 20 - info, 30 - warning, 40 - error, 50 - critical) (default 20)
```
