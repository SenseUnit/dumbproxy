package auth

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"

	clog "github.com/SenseUnit/dumbproxy/log"
)

type StaticRejectAuth struct {
	code   int
	body   string
	hdrs   string
	logger *clog.CondLogger
}

func NewStaticRejectAuth(u *url.URL, logger *clog.CondLogger) (*StaticRejectAuth, error) {
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, err
	}
	code := 403
	if values.Has("code") {
		parsedCode, err := strconv.Atoi(values.Get("code"))
		if err != nil {
			return nil, fmt.Errorf("unable to parse code parameter: %w", err)
		}
		code = parsedCode
	}
	return &StaticRejectAuth{
		code:   code,
		body:   values.Get("body"),
		hdrs:   values.Get("headers"),
		logger: logger,
	}, nil
}

func (a *StaticRejectAuth) Validate(ctx context.Context, w http.ResponseWriter, r *http.Request) (string, bool) {
	if a.hdrs != "" {
		f, err := os.Open(a.hdrs)
		if err != nil {
			a.logger.Error("unable to open file with auth rejection headers: %v", err)
		} else {
			defer f.Close()
			if err := applyHeaders(f, w.Header()); err != nil {
				a.logger.Error("header processing failed: %v", err)
			}

		}
	}
	w.WriteHeader(a.code)
	if a.body != "" {
		f, err := os.Open(a.body)
		if err != nil {
			a.logger.Error("unable to open file with auth rejection body: %v", err)
			return "", false
		}
		defer f.Close()
		_, err = io.Copy(w, f)
		if err != nil {
			a.logger.Debug("auth rejection body write failed: %v", err)
		}
	}
	return "", false
}

func applyHeaders(r io.Reader, h http.Header) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Bytes()
		name, value, found := bytes.Cut(line, []byte{':'})
		if found {
			value = bytes.TrimLeft(value, " \t")
			if len(value) == 0 {
				// Explicitly disabled header
				h[string(name)] = nil
			} else {
				// Normal header value
				h[string(name)] = append(h[string(name)], string(value))
			}
		} else {
			name, _, found := bytes.Cut(line, []byte{';'})
			if found {
				// send a header with an empty value
				h[string(name)] = append(h[string(name)], "")
			} else {
				return fmt.Errorf("malformed header line %q", string(line))
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("header parsing failed: %w", err)
	}
	return nil
}

func (_ *StaticRejectAuth) Valid(_, _, _ string) bool {
	return false
}

func (_ *StaticRejectAuth) Close() error {
	return nil
}
