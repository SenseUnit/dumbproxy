package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/valkey-io/valkey-go"

	clog "github.com/SenseUnit/dumbproxy/log"
)

type ValkeyAuth struct {
	logger       *clog.CondLogger
	hiddenDomain string
	c            valkey.Client
	keyPrefix    string
	stopOnce     sync.Once
	next         Auth
}

func NewValkeyAuth(param_url *url.URL, logger *clog.CondLogger) (*ValkeyAuth, error) {
	values, err := url.ParseQuery(param_url.RawQuery)
	if err != nil {
		return nil, err
	}
	auth := &ValkeyAuth{
		logger:       logger,
		hiddenDomain: strings.ToLower(values.Get("hidden_domain")),
		keyPrefix:    values.Get("key_prefix"),
	}
	opts, err := valkey.ParseURL(values.Get("url"))
	if err != nil {
		return nil, fmt.Errorf("valkey server URL parsing failed: %w", err)
	}
	client, err := valkey.NewClient(opts)
	if err != nil {
		return nil, fmt.Errorf("unable to create valkey client: %w", err)
	}
	auth.c = client
	if nextAuth := values.Get("else"); nextAuth != "" {
		nap, err := NewAuth(nextAuth, logger)
		if err != nil {
			return nil, fmt.Errorf("chained auth provider construction failed: %w", err)
		}
		auth.next = nap
	}
	return auth, nil
}

func (auth *ValkeyAuth) Valid(user, password, userAddr string) bool {
	ctx, cl := context.WithTimeout(context.Background(), 10*time.Second)
	defer cl()
	encodedPasswd, err := auth.c.Do(ctx, auth.c.B().Get().Key(auth.keyPrefix+user).Build()).ToString()
	if err != nil {
		auth.logger.Debug("error fetching key %q from Valkey: %v", auth.keyPrefix+user, err)
		return tryValid(auth.next, auth.logger, user, password, userAddr)
	}
	matcher, err := makePasswdMatcher(encodedPasswd)
	if err != nil {
		auth.logger.Debug("can't create password matcher from Valkey key %q: %v", auth.keyPrefix+user, err)
		return tryValid(auth.next, auth.logger, user, password, userAddr)
	}

	return matcher.MatchesPassword(password) || tryValid(auth.next, auth.logger, user, password, userAddr)
}

func (auth *ValkeyAuth) Validate(ctx context.Context, wr http.ResponseWriter, req *http.Request) (string, bool) {
	hdr := req.Header.Get("Proxy-Authorization")
	if hdr == "" {
		return requireBasicAuth(ctx, wr, req, auth.hiddenDomain, auth.next)
	}
	hdr_parts := strings.SplitN(hdr, " ", 2)
	if len(hdr_parts) != 2 || strings.ToLower(hdr_parts[0]) != "basic" {
		return requireBasicAuth(ctx, wr, req, auth.hiddenDomain, auth.next)
	}

	token := hdr_parts[1]
	data, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return requireBasicAuth(ctx, wr, req, auth.hiddenDomain, auth.next)
	}

	pair := strings.SplitN(string(data), ":", 2)
	if len(pair) != 2 {
		return requireBasicAuth(ctx, wr, req, auth.hiddenDomain, auth.next)
	}

	login := pair[0]
	password := pair[1]

	encodedPasswd, err := auth.c.Do(ctx, auth.c.B().Get().Key(auth.keyPrefix+login).Build()).ToString()
	if err != nil {
		auth.logger.Debug("error fetching key %q from Valkey: %v", auth.keyPrefix+login, err)
		return requireBasicAuth(ctx, wr, req, auth.hiddenDomain, auth.next)
	}
	matcher, err := makePasswdMatcher(encodedPasswd)
	if err != nil {
		auth.logger.Debug("can't create password matcher from Valkey key %q: %v", auth.keyPrefix+login, err)
		return requireBasicAuth(ctx, wr, req, auth.hiddenDomain, auth.next)
	}

	if matcher.MatchesPassword(password) {
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
	return requireBasicAuth(ctx, wr, req, auth.hiddenDomain, auth.next)
}

func (auth *ValkeyAuth) Close() error {
	var err error
	auth.stopOnce.Do(func() {
		if auth.next != nil {
			if closeErr := auth.next.Close(); closeErr != nil {
				err = closeErr
			}
		}
		auth.c.Close()
	})
	return err
}
