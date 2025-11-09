package dialer

import (
	"fmt"
	"net/url"

	xproxy "golang.org/x/net/proxy"
)

func ChainFromURL(u *url.URL, base xproxy.Dialer) (xproxy.Dialer, error) {
	var d Dialer = MaybeWrapWithContextDialer(base)
	params, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, err
	}
	for i, proxySpec := range params["next"] {
		newDialer, err := ProxyDialerFromURL(proxySpec, d)
		if err != nil {
			return nil, fmt.Errorf("unable to construct proxy chain: proxy spec #%d %q construction failed: %w", i+1, proxySpec, err)
		}
		d = newDialer
	}
	return d, nil
}
