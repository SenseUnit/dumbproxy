package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tg123/go-htpasswd"

	clog "github.com/SenseUnit/dumbproxy/log"
)

type pwFile struct {
	file         *htpasswd.File
	lastReloaded time.Time
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

	reloadIntervalOption := values.Get("reload")
	reloadInterval, err := time.ParseDuration(reloadIntervalOption)
	if err != nil {
		reloadInterval = 0
	}
	if reloadInterval == 0 {
		reloadInterval = 15 * time.Second
	}
	if reloadInterval > 0 {
		go auth.reloadLoop(reloadInterval)
	}

	return auth, nil
}

func (auth *BasicAuth) reload() error {
	auth.logger.Info("reloading password file from %q...", auth.pwFilename)
	newPwFile, err := htpasswd.New(auth.pwFilename, htpasswd.DefaultSystems, func(parseErr error) {
		auth.logger.Error("failed to parse line in %q: %v", auth.pwFilename, parseErr)
	})
	if err != nil {
		return err
	}

	now := time.Now()

	newPw := &pwFile{
		file:         newPwFile,
		lastReloaded: now,
	}
	auth.pw.Store(newPw)
	auth.logger.Info("password file reloaded.")

	return nil
}

func fileModTime(filename string) (time.Time, error) {
	f, err := os.Open(filename)
	if err != nil {
		return time.Time{}, fmt.Errorf("fileModTime(): can't open file %q: %w", filename, err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return time.Time{}, fmt.Errorf("fileModTime(): can't stat file %q: %w", filename, err)
	}

	return fi.ModTime(), nil
}

func (auth *BasicAuth) condReload() error {
	reload := func() bool {
		pwFileModTime, err := fileModTime(auth.pwFilename)
		if err != nil {
			auth.logger.Warning("can't get password file modtime: %v", err)
			return true
		}
		return !pwFileModTime.Before(auth.pw.Load().lastReloaded)
	}()
	if reload {
		return auth.reload()
	}
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
			auth.condReload()
		}
	}
}

func requireBasicAuth(wr http.ResponseWriter, req *http.Request, hidden_domain string) {
	if hidden_domain != "" &&
		(subtle.ConstantTimeCompare([]byte(req.URL.Host), []byte(hidden_domain)) != 1 &&
			subtle.ConstantTimeCompare([]byte(req.Host), []byte(hidden_domain)) != 1) {
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
