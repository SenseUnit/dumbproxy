package dialer

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/Snawoot/secache"
	xproxy "golang.org/x/net/proxy"
)

type dialerCacheKey struct {
	url  string
	next xproxy.Dialer
}

type dialerCacheValue struct {
	expires time.Time
	dialer  xproxy.Dialer
	err     error
}

var dialerCache = secache.New[dialerCacheKey, *dialerCacheValue](3, func(key dialerCacheKey, val *dialerCacheValue) bool {
	return time.Now().Before(val.expires)
})

func GetCachedDialer(u *url.URL, next xproxy.Dialer) (xproxy.Dialer, error) {
	params, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, err
	}
	if !params.Has("url") {
		return nil, errors.New("cached dialer: no \"url\" parameter specified")
	}
	parsedURL, err := url.Parse(params.Get("url"))
	if err != nil {
		return nil, fmt.Errorf("unable to parse proxy URL: %w", err)
	}
	if !params.Has("ttl") {
		return nil, errors.New("cached dialer: no \"ttl\" parameter specified")
	}
	ttl, err := time.ParseDuration(params.Get("ttl"))
	if err != nil {
		return nil, fmt.Errorf("cached dialer: unable to parse TTL duration %q: %w", params.Get("ttl"), err)
	}
	item := dialerCache.GetOrCreate(
		dialerCacheKey{
			url:  params.Get("url"),
			next: next,
		},
		func() *dialerCacheValue {
			dialer, err := xproxy.FromURL(parsedURL, next)
			return &dialerCacheValue{
				expires: time.Now().Add(ttl),
				dialer:  dialer,
				err:     err,
			}
		},
	)
	return item.dialer, item.err
}
