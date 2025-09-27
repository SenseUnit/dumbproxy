package auth

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	clog "github.com/SenseUnit/dumbproxy/log"

	"github.com/redis/go-redis/v9"
)

type RedisAuth struct {
	logger       *clog.CondLogger
	hiddenDomain string
	r            redis.Cmdable
	keyPrefix    string
}

func NewRedisAuth(param_url *url.URL, cluster bool, logger *clog.CondLogger) (*RedisAuth, error) {
	values, err := url.ParseQuery(param_url.RawQuery)
	if err != nil {
		return nil, err
	}
	auth := &RedisAuth{
		logger:       logger,
		hiddenDomain: strings.ToLower(values.Get("hidden_domain")),
		keyPrefix:    values.Get("key_prefix"),
	}
	if cluster {
		opts, err := redis.ParseClusterURL(values.Get("url"))
		if err != nil {
			return nil, err
		}
		auth.r = redis.NewClusterClient(opts)
	} else {
		opts, err := redis.ParseURL(values.Get("url"))
		if err != nil {
			return nil, err
		}
		auth.r = redis.NewClient(opts)
	}
	return auth, nil
}

func (auth *RedisAuth) Valid(user, password, userAddr string) bool {
	ctx, cl := context.WithTimeout(context.Background(), 10*time.Second)
	defer cl()
	encodedPasswd, err := auth.r.Get(ctx, auth.keyPrefix+user).Result()
	if err != nil {
		auth.logger.Debug("error fetching key %q from Redis: %v", auth.keyPrefix+user, err)
		return false
	}
	matcher, err := makePasswdMatcher(encodedPasswd)
	if err != nil {
		auth.logger.Debug("can't create password matcher from Redis key %q: %v", auth.keyPrefix+user, err)
		return false
	}

	return matcher.MatchesPassword(password)
}

func (auth *RedisAuth) Validate(ctx context.Context, wr http.ResponseWriter, req *http.Request) (string, bool) {
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

	encodedPasswd, err := auth.r.Get(ctx, auth.keyPrefix+login).Result()
	if err != nil {
		auth.logger.Debug("error fetching key %q from Redis: %v", auth.keyPrefix+login, err)
		requireBasicAuth(wr, req, auth.hiddenDomain)
		return "", false
	}
	matcher, err := makePasswdMatcher(encodedPasswd)
	if err != nil {
		auth.logger.Debug("can't create password matcher from Redis key %q: %v", auth.keyPrefix+login, err)
		requireBasicAuth(wr, req, auth.hiddenDomain)
		return "", false
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
	requireBasicAuth(wr, req, auth.hiddenDomain)
	return "", false
}

func (auth *RedisAuth) Stop() {
}
