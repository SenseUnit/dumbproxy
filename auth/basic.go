package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tg123/go-htpasswd"

	clog "github.com/SenseUnit/dumbproxy/log"
)

type pwFile struct {
	file    *htpasswd.File
	modTime time.Time
}
type BasicAuth struct {
	pw           atomic.Pointer[pwFile]
	pwFilename   string
	logger       *clog.CondLogger
	hiddenDomain string
	stopOnce     sync.Once
	stopChan     chan struct{}
}

func NewBasicFileAuth(param_url *url.URL, logger *clog.CondLogger) (*BasicAuth, error) {
	values, err := url.ParseQuery(param_url.RawQuery)
	if err != nil {
		return nil, err
	}
	filename := values.Get("path")
	if filename == "" {
		return nil, errors.New("\"path\" parameter is missing from auth config URI")
	}

	auth := &BasicAuth{
		hiddenDomain: strings.ToLower(values.Get("hidden_domain")),
		pwFilename:   filename,
		logger:       logger,
		stopChan:     make(chan struct{}),
	}

	if err := auth.reload(); err != nil {
		return nil, fmt.Errorf("unable to load initial password list: %w", err)
	}

	reloadInterval := 15 * time.Second
	if reloadIntervalOption := values.Get("reload"); reloadIntervalOption != "" {
		parsedInterval, err := time.ParseDuration(reloadIntervalOption)
		if err != nil {
			logger.Warning("unable to parse reload interval: %v. using default value.", err)
		}
		reloadInterval = parsedInterval
	}
	if reloadInterval > 0 {
		go auth.reloadLoop(reloadInterval)
	}

	return auth, nil
}

func (auth *BasicAuth) reload() error {
	var oldModTime time.Time
	if oldPw := auth.pw.Load(); oldPw != nil {
		oldModTime = oldPw.modTime
	}

	f, modTime, err := openIfModified(auth.pwFilename, oldModTime)
	if err != nil {
		return err
	}
	if f == nil {
		// no changes since last modTime
		return nil
	}

	auth.logger.Info("reloading password file from %q...", auth.pwFilename)
	newPwFile, err := htpasswd.NewFromReader(f, htpasswd.DefaultSystems, func(parseErr error) {
		auth.logger.Error("failed to parse line in %q: %v", auth.pwFilename, parseErr)
	})
	if err != nil {
		return err
	}

	newPw := &pwFile{
		file:    newPwFile,
		modTime: modTime,
	}
	auth.pw.Store(newPw)
	auth.logger.Info("password file reloaded.")

	return nil
}

func (auth *BasicAuth) reloadLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-auth.stopChan:
			return
		case <-ticker.C:
			if err := auth.reload(); err != nil {
				auth.logger.Error("reload failed: %v", err)
			}
		}
	}
}

func matchHiddenDomain(host, hidden_domain string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return subtle.ConstantTimeCompare([]byte(host), []byte(hidden_domain)) == 1
}

func requireBasicAuth(wr http.ResponseWriter, req *http.Request, hidden_domain string) {
	if hidden_domain != "" &&
		!matchHiddenDomain(req.URL.Host, hidden_domain) &&
		!matchHiddenDomain(req.Host, hidden_domain) {
		http.Error(wr, BAD_REQ_MSG, http.StatusBadRequest)
	} else {
		wr.Header().Set("Proxy-Authenticate", `Basic realm="dumbproxy"`)
		wr.Header().Set("Content-Length", strconv.Itoa(len([]byte(AUTH_REQUIRED_MSG))))
		wr.WriteHeader(407)
		wr.Write([]byte(AUTH_REQUIRED_MSG))
	}
}

func (auth *BasicAuth) Validate(wr http.ResponseWriter, req *http.Request) (string, bool) {
	hdr := req.Header.Get("Proxy-Authorization")
	if hdr == "" {
		requireBasicAuth(wr, req, auth.hiddenDomain)
		return "", false
	}
	hdr_parts := strings.SplitN(hdr, " ", 2)
	if len(hdr_parts) != 2 || strings.ToLower(hdr_parts[0]) != "basic" {
		requireBasicAuth(wr, req, auth.hiddenDomain)
		return "", false
	}

	token := hdr_parts[1]
	data, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		requireBasicAuth(wr, req, auth.hiddenDomain)
		return "", false
	}

	pair := strings.SplitN(string(data), ":", 2)
	if len(pair) != 2 {
		requireBasicAuth(wr, req, auth.hiddenDomain)
		return "", false
	}

	login := pair[0]
	password := pair[1]

	pwFile := auth.pw.Load().file

	if pwFile.Match(login, password) {
		if auth.hiddenDomain != "" &&
			(req.Host == auth.hiddenDomain || req.URL.Host == auth.hiddenDomain) {
			wr.Header().Set("Content-Length", strconv.Itoa(len([]byte(AUTH_TRIGGERED_MSG))))
			wr.Header().Set("Pragma", "no-cache")
			wr.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			wr.Header().Set("Expires", EPOCH_EXPIRE)
			wr.Header()["Date"] = nil
			wr.WriteHeader(http.StatusOK)
			wr.Write([]byte(AUTH_TRIGGERED_MSG))
			return "", false
		} else {
			return login, true
		}
	}
	requireBasicAuth(wr, req, auth.hiddenDomain)
	return "", false
}

func (auth *BasicAuth) Stop() {
	auth.stopOnce.Do(func() {
		close(auth.stopChan)
	})
}
