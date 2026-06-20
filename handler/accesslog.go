package handler

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

type accessLogResponseWriter struct {
	http.ResponseWriter
	status int
}

func newAccessLogResponseWriter(w http.ResponseWriter) *accessLogResponseWriter {
	return &accessLogResponseWriter{ResponseWriter: w}
}

func (w *accessLogResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
		w.ResponseWriter.WriteHeader(status)
	}
}

func (w *accessLogResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}

func (w *accessLogResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *accessLogResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("connection doesn't support hijacking")
	}
	return hj.Hijack()
}

func markAccessLogStatus(w http.ResponseWriter, status int) {
	if lw, ok := w.(*accessLogResponseWriter); ok && lw.status == 0 {
		lw.status = status
	}
}

func accessLogTarget(req *http.Request) string {
	if req.Method == http.MethodConnect {
		if req.RequestURI != "" {
			return req.RequestURI
		}
		if req.URL != nil && req.URL.Host != "" {
			return req.URL.Host
		}
	}
	if req.URL == nil {
		return ""
	}
	return req.URL.String()
}

func accessLogStatus(status int) string {
	if status == 0 {
		return "-"
	}
	text := http.StatusText(status)
	if text == "" {
		return strconv.Itoa(status)
	}
	return fmt.Sprintf("%d %s", status, text)
}

func accessLogDuration(start time.Time) time.Duration {
	return time.Since(start).Round(time.Millisecond)
}
