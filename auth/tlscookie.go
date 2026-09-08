package auth

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/hashicorp/go-multierror"

	clog "github.com/SenseUnit/dumbproxy/log"
	"github.com/SenseUnit/dumbproxy/tlsutil"
)

type sessionValidator interface {
	Valid(sessionID, _, userAddr string) bool
	Close() error
}

type TLSCookieAuth struct {
	logger          *clog.CondLogger
	stopOnce        sync.Once
	next            Auth
	reject          Auth
	lookup          sessionValidator
	hiddenDomain    string
	lsMux           sync.RWMutex
	learnedSessions map[tlsutil.TLSSessionID]struct{}
}

func NewTLSCookieAuth(param_url *url.URL, logger *clog.CondLogger) (*TLSCookieAuth, error) {
	values, err := url.ParseQuery(param_url.RawQuery)
	if err != nil {
		return nil, err
	}
	auth := &TLSCookieAuth{
		logger:          logger,
		hiddenDomain:    strings.ToLower(values.Get("hidden_domain")),
		learnedSessions: make(map[tlsutil.TLSSessionID]struct{}),
	}
	if lookupURL := values.Get("lookup"); lookupURL != "" {
		lookupAuth, err := NewAuth(lookupURL, logger)
		if err != nil {
			return nil, fmt.Errorf("unable to construct lookup provider for TLS cookie auth provider: %w", err)
		}
		lookup, ok := lookupAuth.(sessionValidator)
		if !ok {
			lookupAuth.Close()
			defer auth.Close()
			return nil, fmt.Errorf("unable to construct TLS cookie auth provider: provided lookup provider %q is not suitable for session validation", lookupURL)
		}
		auth.lookup = lookup
	}
	if nextAuth := values.Get("next"); nextAuth != "" {
		nap, err := NewAuth(nextAuth, logger)
		if err != nil {
			defer auth.Close()
			return nil, fmt.Errorf("chained auth provider construction failed: %w", err)
		}
		auth.next = nap
	}
	if nextAuth := values.Get("else"); nextAuth != "" {
		nap, err := NewAuth(nextAuth, logger)
		if err != nil {
			defer auth.Close()
			return nil, fmt.Errorf("chained auth provider construction failed: %w", err)
		}
		auth.reject = nap
	}
	return auth, nil
}

func (auth *TLSCookieAuth) checkLearned(sessionID tlsutil.TLSSessionID) bool {
	auth.lsMux.RLock()
	defer auth.lsMux.RUnlock()
	_, ok := auth.learnedSessions[sessionID]
	return ok
}

func (auth *TLSCookieAuth) addLearned(sessionID tlsutil.TLSSessionID) {
	auth.lsMux.Lock()
	defer auth.lsMux.Unlock()
	auth.learnedSessions[sessionID] = struct{}{}
}

func (auth *TLSCookieAuth) Validate(ctx context.Context, wr http.ResponseWriter, req *http.Request) (string, bool) {
	conn, ok := tlsutil.ConnFromContext(ctx)
	if !ok {
		auth.logger.Debug("tlscookie: no conn found in context for %s", req.RemoteAddr)
		return auth.handleReject(ctx, wr, req)
	}
	sessionID, ok := tlsutil.GetTLSSessionID(conn)
	if !ok {
		auth.logger.Debug("tlscookie: no session ID recovered for %s", req.RemoteAddr)
		return auth.handleReject(ctx, wr, req)
	}
	if auth.hiddenDomain != "" {
		if matchHiddenDomain(req.Host, auth.hiddenDomain) || matchHiddenDomain(req.URL.Host, auth.hiddenDomain) {
			auth.logger.Debug("tlscookie: session %x from %s requested magic domain", sessionID, req.RemoteAddr)
			auth.addLearned(sessionID)
			wr.Header().Set("Pragma", "no-cache")
			wr.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			wr.Header().Set("Expires", EPOCH_EXPIRE)
			wr.WriteHeader(http.StatusBadRequest)
			wr.Write([]byte(AUTH_TRIGGERED_MSG))
			return "", false
		}
		if auth.checkLearned(sessionID) {
			auth.logger.Debug("tlscookie: session %x from %s passed because it is in learned set", sessionID, req.RemoteAddr)
			return auth.handleSuccess(ctx, wr, req, sessionID)
		}
	}
	if auth.lookup != nil && auth.lookup.Valid(hex.EncodeToString(sessionID[:]), "", req.RemoteAddr) {
		auth.logger.Debug("tlscookie: session %x from %s passed because external lookup said yay", sessionID, req.RemoteAddr)
		return auth.handleSuccess(ctx, wr, req, sessionID)
	}
	auth.logger.Info("tlscookie: session ID %x from %s is not permitted", sessionID, req.RemoteAddr)
	return auth.handleReject(ctx, wr, req)
}

func (auth *TLSCookieAuth) handleSuccess(ctx context.Context, wr http.ResponseWriter, req *http.Request, sessionID tlsutil.TLSSessionID) (string, bool) {
	if auth.next != nil {
		return auth.next.Validate(ctx, wr, req)
	}
	return fmt.Sprintf("tlscookie:%x", sessionID), true
}

func (auth *TLSCookieAuth) handleReject(ctx context.Context, wr http.ResponseWriter, req *http.Request) (string, bool) {
	if auth.reject != nil {
		return auth.reject.Validate(ctx, wr, req)
	}
	http.Error(wr, BAD_REQ_MSG, http.StatusBadRequest)
	return "", false
}

func (auth *TLSCookieAuth) Close() error {
	var err error
	auth.stopOnce.Do(func() {
		if auth.lookup != nil {
			if closeErr := auth.lookup.Close(); closeErr != nil {
				err = multierror.Append(err, closeErr)
			}
		}
		if auth.next != nil {
			if closeErr := auth.next.Close(); closeErr != nil {
				err = multierror.Append(err, closeErr)
			}
		}
		if auth.reject != nil {
			if closeErr := auth.reject.Close(); closeErr != nil {
				err = multierror.Append(err, closeErr)
			}
		}
	})
	return err
}
