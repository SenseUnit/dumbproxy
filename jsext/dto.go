package jsext

import (
	"mime/multipart"
	"net/http"
	"net/url"
)

type JSRequestInfo struct {
	Method           string          `json:"method"`
	URL              string          `json:"url"`
	Proto            string          `json:"proto"`
	ProtoMajor       int             `json:"protoMajor"`
	ProtoMinor       int             `json:"protoMinor"`
	Header           http.Header     `json:"header"`
	ContentLength    int64           `json:"contentLength"`
	TransferEncoding []string        `json:"transferEncoding"`
	Host             string          `json:"host"`
	Form             url.Values      `json:"form"`
	PostForm         url.Values      `json:"portForm"`
	MultipartForm    *multipart.Form `json:"multipartForm"`
	Trailer          http.Header     `json:"trailer"`
	RemoteAddr       string          `json:"remoteAddr"`
	RequestURI       string          `json:"requestURI"`
}

func JSRequestInfoFromRequest(req *http.Request) *JSRequestInfo {
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
		Form:             req.Form,
		PostForm:         req.PostForm,
		MultipartForm:    req.MultipartForm,
		Trailer:          req.Trailer,
		RemoteAddr:       req.RemoteAddr,
		RequestURI:       req.RequestURI,
	}
}
