package auth

import "net/http"

type NoAuth struct{}

func (_ NoAuth) Validate(wr http.ResponseWriter, req *http.Request) (string, bool) {
	return "", true
}

func (_ NoAuth) Stop() {}
