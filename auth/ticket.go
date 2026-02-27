package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"github.com/hashicorp/go-multierror"

	clog "github.com/SenseUnit/dumbproxy/log"
	"github.com/SenseUnit/dumbproxy/tlsutil"
)

type TLSTicketAuth struct {
	logger   *clog.CondLogger
	stopOnce sync.Once
	next     Auth
	reject   Auth
}

func NewTLSTicketAuth(param_url *url.URL, logger *clog.CondLogger) (*TLSTicketAuth, error) {
	values, err := url.ParseQuery(param_url.RawQuery)
	if err != nil {
		return nil, err
	}
	auth := &TLSTicketAuth{
		logger: logger,
	}
	if nextAuth := values.Get("next"); nextAuth != "" {
		nap, err := NewAuth(nextAuth, logger)
		if err != nil {
			return nil, fmt.Errorf("chained auth provider construction failed: %w", err)
		}
		auth.next = nap
	}
	if nextAuth := values.Get("else"); nextAuth != "" {
		nap, err := NewAuth(nextAuth, logger)
		if err != nil {
			return nil, fmt.Errorf("chained auth provider construction failed: %w", err)
		}
		auth.reject = nap
	}
	return auth, nil
}

func (auth *TLSTicketAuth) Validate(ctx context.Context, wr http.ResponseWriter, req *http.Request) (string, bool) {
	if !tlsutil.NonDefaultKeyUsedFromContext(ctx) {
		return auth.handleReject(ctx, wr, req)
	}
	if auth.next != nil {
		return auth.next.Validate(ctx, wr, req)
	}
	return "", true
}

func (auth *TLSTicketAuth) handleReject(ctx context.Context, wr http.ResponseWriter, req *http.Request) (string, bool) {
	if auth.reject != nil {
		return auth.reject.Validate(ctx, wr, req)
	}
	http.Error(wr, BAD_REQ_MSG, http.StatusBadRequest)
	return "", false
}

func (auth *TLSTicketAuth) Close() error {
	var err error
	auth.stopOnce.Do(func() {
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
