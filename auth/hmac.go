package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	clog "github.com/SenseUnit/dumbproxy/log"
)

const (
	HMACSignaturePrefix = "dumbproxy grant token v1"
	HMACSignatureSize   = 32
	HMACTimestampSize   = 8
	EnvVarHMACSecret    = "DUMBPROXY_HMAC_SECRET"
)

type HMACAuth struct {
	secret       []byte
	hiddenDomain string
	logger       *clog.CondLogger
	stopOnce     sync.Once
	next         Auth
}

func NewHMACAuth(param_url *url.URL, logger *clog.CondLogger) (*HMACAuth, error) {
	values, err := url.ParseQuery(param_url.RawQuery)
	if err != nil {
		return nil, err
	}

	hexSecret := os.Getenv(EnvVarHMACSecret)
	if hs := values.Get("secret"); hs != "" {
		hexSecret = hs
	}

	if hexSecret == "" {
		return nil, errors.New("no HMAC secret specified. Please specify \"secret\" parameter for auth provider or set " + EnvVarHMACSecret + " environment variable.")
	}

	secret, err := hex.DecodeString(hexSecret)
	if err != nil {
		return nil, fmt.Errorf("can't hex-decode HMAC secret: %w", err)
	}

	auth := &HMACAuth{
		secret:       secret,
		logger:       logger,
		hiddenDomain: strings.ToLower(values.Get("hidden_domain")),
	}

	if nextAuth := values.Get("else"); nextAuth != "" {
		nap, err := NewAuth(nextAuth, logger)
		if err != nil {
			return nil, fmt.Errorf("chained auth provider construction failed: %w", err)
		}
		auth.next = nap
	}

	return auth, nil
}

type HMACToken struct {
	Expire    int64
	Signature [HMACSignatureSize]byte
}

func VerifyHMACLoginAndPassword(secret []byte, login, password string) bool {
	marshaledToken, err := base64.RawURLEncoding.DecodeString(password)
	if err != nil {
		return false
	}

	var token HMACToken
	_, err = binary.Decode(marshaledToken, binary.BigEndian, &token)
	if err != nil {
		return false
	}

	if time.Unix(token.Expire, 0).Before(time.Now()) {
		return false
	}

	expectedMAC := CalculateHMACSignature(secret, login, token.Expire)
	return hmac.Equal(token.Signature[:], expectedMAC)
}

func (auth *HMACAuth) Valid(user, password, userAddr string) bool {
	return VerifyHMACLoginAndPassword(auth.secret, user, password) || tryValid(auth.next, auth.logger, user, password, userAddr)
}

func (auth *HMACAuth) Validate(ctx context.Context, wr http.ResponseWriter, req *http.Request) (string, bool) {
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

	if VerifyHMACLoginAndPassword(auth.secret, login, password) {
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

func (auth *HMACAuth) Close() error {
	var err error
	auth.stopOnce.Do(func() {
		if auth.next != nil {
			err = auth.next.Close()
		}
	})
	return err
}

func CalculateHMACSignature(secret []byte, username string, expire int64) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(HMACSignaturePrefix))
	mac.Write([]byte(username))
	binary.Write(mac, binary.BigEndian, expire)
	return mac.Sum(nil)
}
