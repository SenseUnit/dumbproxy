package auth

import "net/http"

type CertAuth struct{}

func (_ CertAuth) Validate(wr http.ResponseWriter, req *http.Request) (string, bool) {
	if req.TLS == nil || len(req.TLS.VerifiedChains) < 1 || len(req.TLS.VerifiedChains[0]) < 1 {
		http.Error(wr, BAD_REQ_MSG, http.StatusBadRequest)
		return "", false
	} else {
		return req.TLS.VerifiedChains[0][0].Subject.String(), true
	}
}

func (_ CertAuth) Stop() {}
