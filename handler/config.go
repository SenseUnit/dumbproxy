package handler

import (
	"github.com/SenseUnit/dumbproxy/auth"
	clog "github.com/SenseUnit/dumbproxy/log"
)

type Config struct {
	// Dialer optionally specifies dialer to use for creating
	// connections originating from proxy.
	Dialer HandlerDialer
	// Auth specifies request validator used to verify users
	// and return their username
	Auth auth.Auth
	// Logger specifies optional custom logger
	Logger *clog.CondLogger
	// UserIPHints specifies whether allow IP hints set by user or not
	UserIPHints bool
}
