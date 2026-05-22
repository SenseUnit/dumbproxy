package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewResponseStatic(t *testing.T) {
	response, err := NewResponse("static://?code=204", nil)
	if err != nil {
		t.Fatalf("NewResponse returned error: %v", err)
	}

	rr := httptest.NewRecorder()
	_, ok := response.Validate(context.Background(), rr, httptest.NewRequest(http.MethodGet, "/", nil))

	if ok {
		t.Fatalf("static response should not authorize requests")
	}
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusNoContent)
	}
}

func TestNewResponseRejectStaticIsInvalid(t *testing.T) {
	if _, err := NewResponse("reject-static://?code=204", nil); err == nil {
		t.Fatalf("NewResponse accepted reject-static scheme")
	}
}

func TestNewRejectAuthStaticIsInvalid(t *testing.T) {
	if _, err := NewRejectAuth("static://?code=403", nil); err == nil {
		t.Fatalf("NewRejectAuth accepted static scheme")
	}
}
