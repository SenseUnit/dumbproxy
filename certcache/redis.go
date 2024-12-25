package certcache

import (
	"context"

	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/acme/autocert"
)

type RedisCache struct {
	r   redis.Cmdable
	pfx string
}

func NewRedisCache(r redis.Cmdable, prefix string) *RedisCache {
	return &RedisCache{
		r:   r,
		pfx: prefix,
	}
}

func (r *RedisCache) Get(ctx context.Context, key string) ([]byte, error) {
	res, err := r.r.Get(ctx, r.pfx+key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, autocert.ErrCacheMiss
		}
		return nil, err
	}
	return res, nil
}

func (r *RedisCache) Put(ctx context.Context, key string, data []byte) error {
	return r.r.Set(ctx, r.pfx+key, data, 0).Err()
}

func (r *RedisCache) Delete(ctx context.Context, key string) error {
	return r.r.Del(ctx, r.pfx+key).Err()
}

func RedisCacheFromURL(url string, prefix string) (*RedisCache, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}

	r := redis.NewClient(opts)
	return NewRedisCache(r, prefix), nil
}

func RedisClusterCacheFromURL(url string, prefix string) (*RedisCache, error) {
	opts, err := redis.ParseClusterURL(url)
	if err != nil {
		return nil, err
	}

	r := redis.NewClusterClient(opts)
	return NewRedisCache(r, prefix), nil
}
