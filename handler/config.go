package handler

import (
	"github.com/SenseUnit/dumbproxy/auth"
	clog "github.com/SenseUnit/dumbproxy/log"
)

type Config struct {
	Dialer      HandlerDialer
	Auth        auth.Auth
	Logger      *clog.CondLogger
	UserIPHints bool
}
