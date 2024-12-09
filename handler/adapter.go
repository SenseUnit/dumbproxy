package handler

import (
	"io"
	"net/http"
)

type wrappedH2 struct {
	r io.ReadCloser
	w io.Writer
}

func wrapH2(r io.ReadCloser, w io.Writer) wrappedH2 {
	return wrappedH2{
		r: r,
		w: w,
	}
}

func (w wrappedH2) Read(p []byte) (n int, err error) {
	return w.r.Read(p)
}

func (w wrappedH2) Write(p []byte) (n int, err error) {
	n, err = w.w.Write(p)
	if err != nil {
		return
	}
	if f, ok := w.w.(http.Flusher); ok {
		f.Flush()
	}
	return
}

func (w wrappedH2) Close() error {
	// can't really close response writer, but at least we can disrupt copy
	// closing Reader
	return w.r.Close()
}

var _ io.ReadWriteCloser = wrappedH2{}

type wrappedH1ReqBody struct {
	r io.ReadCloser
}

func wrapH1ReqBody(r io.ReadCloser) wrappedH1ReqBody {
	return wrappedH1ReqBody{
		r: r,
	}
}

func (w wrappedH1ReqBody) Read(p []byte) (n int, err error) {
	return w.r.Read(p)
}

func (w wrappedH1ReqBody) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (w wrappedH1ReqBody) Close() error {
	return w.r.Close()
}

func (w wrappedH1ReqBody) CloseWrite() error {
	return nil
}

var _ io.ReadWriteCloser = wrappedH1ReqBody{}
var _ interface{ CloseWrite() error } = wrappedH1ReqBody{}

type h1ReqBodyPipe struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func newH1ReqBodyPipe() h1ReqBodyPipe {
	r, w := io.Pipe()
	return h1ReqBodyPipe{
		r: r,
		w: w,
	}
}

func (w h1ReqBodyPipe) Read(p []byte) (n int, err error) {
	return 0, io.EOF
}

func (w h1ReqBodyPipe) Write(p []byte) (n int, err error) {
	return w.w.Write(p)
}

func (w h1ReqBodyPipe) Close() error {
	return w.CloseWrite()
}

func (w h1ReqBodyPipe) CloseWrite() error {
	return w.w.Close()
}

func (w h1ReqBodyPipe) Body() io.ReadCloser {
	return w.r
}

var _ io.ReadWriteCloser = h1ReqBodyPipe{}
var _ interface{ CloseWrite() error } = h1ReqBodyPipe{}

type wrappedH1RespWriter struct {
	w io.Writer
}

func wrapH1RespWriter(w io.Writer) wrappedH1RespWriter {
	return wrappedH1RespWriter{
		w: w,
	}
}

func (w wrappedH1RespWriter) Read(p []byte) (n int, err error) {
	return 0, io.EOF
}

func (w wrappedH1RespWriter) Write(p []byte) (n int, err error) {
	n, err = w.w.Write(p)
	if f, ok := w.w.(http.Flusher); ok {
		f.Flush()
	}
	return
}

func (w wrappedH1RespWriter) Close() error {
	// can't really close response writer, just make copier return
	// and finish request
	return nil
}

var _ io.ReadWriteCloser = wrappedH1RespWriter{}
