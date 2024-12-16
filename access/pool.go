package access

import (
	"context"
	"net/http"
)

type FilterPool struct {
	pool chan Filter
}

func NewFilterPool(size int, newFilter func() (Filter, error)) (FilterPool, error) {
	size = max(1, size)
	pool := make(chan Filter, size)
	for i := 0; i < size; i++ {
		f, err := newFilter()
		if err != nil {
			return FilterPool{}, err
		}
		pool <- f
	}
	return FilterPool{
		pool: pool,
	}, nil
}

func (p FilterPool) Access(ctx context.Context, req *http.Request, username, network, address string) error {
	f := <-p.pool
	defer func(pool chan Filter, f Filter) {
		pool <- f
	}(p.pool, f)
	return f.Access(ctx, req, username, network, address)
}
