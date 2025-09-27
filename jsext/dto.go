package jsext

import (
	"context"
	"net"
	"net/http"
	"strconv"

	ddto "github.com/SenseUnit/dumbproxy/dialer/dto"
)

type JSRequestInfo struct {
	Method           string      `json:"method"`
	URL              string      `json:"url"`
	Proto            string      `json:"proto"`
	ProtoMajor       int         `json:"protoMajor"`
	ProtoMinor       int         `json:"protoMinor"`
	Header           http.Header `json:"header"`
	ContentLength    int64       `json:"contentLength"`
	TransferEncoding []string    `json:"transferEncoding"`
	Host             string      `json:"host"`
	RemoteAddr       string      `json:"remoteAddr"`
	RequestURI       string      `json:"requestURI"`
}

func JSRequestInfoFromRequest(req *http.Request) *JSRequestInfo {
	if req == nil {
		return nil
	}
	return &JSRequestInfo{
		Method:           req.Method,
		URL:              req.URL.String(),
		Proto:            req.Proto,
		ProtoMajor:       req.ProtoMajor,
		ProtoMinor:       req.ProtoMinor,
		Header:           req.Header,
		ContentLength:    req.ContentLength,
		TransferEncoding: req.TransferEncoding,
		Host:             req.Host,
		RemoteAddr:       req.RemoteAddr,
		RequestURI:       req.RequestURI,
	}
}

type JSDstInfo struct {
	Network      string  `json:"network"`
	OriginalHost string  `json:"originalHost"`
	ResolvedHost *string `json:"resolvedHost"`
	Port         uint16  `json:"port"`
}

func JSDstInfoFromContext(ctx context.Context, network, address string) (*JSDstInfo, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	portNum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, err
	}
	if origDst, ok := ddto.OrigDstFromContext(ctx); ok {
		origHost, _, err := net.SplitHostPort(origDst)
		if err != nil {
			return nil, err
		}
		return &JSDstInfo{
			Network:      network,
			OriginalHost: origHost,
			ResolvedHost: &host,
			Port:         uint16(portNum),
		}, nil
	} else {
		return &JSDstInfo{
			Network:      network,
			OriginalHost: host,
			ResolvedHost: nil,
			Port:         uint16(portNum),
		}, nil
	}
}
