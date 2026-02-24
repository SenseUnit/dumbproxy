package certcache

import (
	"context"
	"fmt"
	"sync"

	"github.com/valkey-io/valkey-go"
	"golang.org/x/crypto/acme/autocert"
)

type ValkeyCache struct {
	c        valkey.Client
	pfx      string
	stopOnce sync.Once
}

func NewValkeyCache(c valkey.Client, prefix string) *ValkeyCache {
	return &ValkeyCache{
		c:   c,
		pfx: prefix,
	}
}

func (c *ValkeyCache) Get(ctx context.Context, key string) ([]byte, error) {
	res, err := c.c.Do(ctx, c.c.B().Get().Key(c.pfx+key).Build()).AsBytes()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return nil, autocert.ErrCacheMiss
		}
		return nil, err
	}
	return res, nil
}

func (c *ValkeyCache) Put(ctx context.Context, key string, data []byte) error {
	return c.c.Do(ctx, c.c.B().Set().Key(c.pfx+key).Value(string(data)).Build()).Error()
}

func (c *ValkeyCache) Delete(ctx context.Context, key string) error {
	return c.c.Do(ctx, c.c.B().Del().Key(c.pfx+key).Build()).Error()
}

func (c *ValkeyCache) Close() error {
	c.stopOnce.Do(func() {
		c.c.Close()
	})
	return nil
}

func ValkeyCacheFromURL(url string, prefix string) (*ValkeyCache, error) {
	opts, err := valkey.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("valkey server URL parsing failed: %w", err)
	}
	client, err := valkey.NewClient(opts)
	if err != nil {
		return nil, fmt.Errorf("unable to create valkey client: %w", err)
	}
	return NewValkeyCache(client, prefix), nil
}
