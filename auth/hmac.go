package auth

import (
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

	return &HMACAuth{
		secret:       secret,
		logger:       logger,
		hiddenDomain: strings.ToLower(values.Get("hidden_domain")),
	}, nil
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

func (auth *HMACAuth) validateToken(login, password string) bool {
	return VerifyHMACLoginAndPassword(auth.secret, login, password)
}

func (auth *HMACAuth) Validate(wr http.ResponseWriter, req *http.Request) (string, bool) {
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

	if auth.validateToken(login, password) {
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

func (auth *HMACAuth) Stop() {
}

func CalculateHMACSignature(secret []byte, username string, expire int64) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(HMACSignaturePrefix))
	mac.Write([]byte(username))
	binary.Write(mac, binary.BigEndian, expire)
	return mac.Sum(nil)
}
