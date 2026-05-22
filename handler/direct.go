package handler

import "net/http"

func isDirectRequest(req *http.Request) bool {
	if req == nil || req.URL == nil || req.Method == http.MethodConnect || req.Method == "GETRANDOM" {
		return false
	}

	return req.URL.Scheme == "" && req.URL.Host == ""
}
