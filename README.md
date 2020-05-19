dumbproxy
=========

Dumbiest HTTP proxy ever.

## Features

* Cross-platform (Windows/Mac OS/Linux/Android (via shell)/\*BSD)
* Zero-configuration
* Supports CONNECT method and forwarding of HTTPS connections

## Installation

#### Binary download

Pre-built binaries available on [releases](https://github.com/Snawoot/dumbproxy/releases/latest) page.

#### From source

Alternatively, you may install dumbproxy from source. Run within source directory

```
go install
```

## Usage

Just run program and it'll start accepting connections on port 8080 (default)

## Synopsis

```
$ ~/go/bin/dumbproxy -h
  -bind-address string
    	HTTP proxy listen address (default ":8080")
  -timeout duration
    	timeout for network operations (default 10s)
  -verbosity int
    	logging verbosity (10 - debug, 20 - info, 30 - warning, 40 - error, 50 - critical) (default 20)
```
