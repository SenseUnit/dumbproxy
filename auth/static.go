package auth

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/tg123/go-htpasswd"
	"golang.org/x/crypto/bcrypt"

	clog "github.com/SenseUnit/dumbproxy/log"
)

func NewStaticAuth(param_url *url.URL, logger *clog.CondLogger) (*BasicAuth, error) {
	values, err := url.ParseQuery(param_url.RawQuery)
	if err != nil {
		return nil, err
	}
	username := values.Get("username")
	if username == "" {
		return nil, errors.New("\"username\" parameter is missing from auth config URI")
	}
	password := values.Get("password")
	if password == "" {
		return nil, errors.New("\"password\" parameter is missing from auth config URI")
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBufferString(username)
	buf.WriteByte(':')
	buf.Write(hashedPassword)

	f, err := htpasswd.NewFromReader(buf, htpasswd.DefaultSystems, func(parseError error) {
		logger.Error("static auth: password entry parse error: %v", err)
	})
	if err != nil {
		return nil, fmt.Errorf("can't instantiate pwFile: %w", err)
	}

	ba := &BasicAuth{
		hiddenDomain: strings.ToLower(values.Get("hidden_domain")),
		logger:       logger,
		stopChan:     make(chan struct{}),
	}
	ba.pw.Store(&pwFile{file: f})
	if nextAuth := values.Get("else"); nextAuth != "" {
		nap, err := NewAuth(nextAuth, logger)
		if err != nil {
			return nil, fmt.Errorf("chained auth provider construction failed: %w", err)
		}
		ba.next = nap
	}
	return ba, nil
}
