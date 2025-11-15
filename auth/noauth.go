package auth

import (
	"context"
	"net/http"
)

type NoAuth struct{}

func (_ NoAuth) Validate(_ context.Context, _ http.ResponseWriter, _ *http.Request) (string, bool) {
	return "", true
}

func (_ NoAuth) Close() error {
	return nil
}
