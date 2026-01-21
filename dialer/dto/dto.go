package dto

import (
	"context"
	"net/http"
)

type boundDialerContextKey struct{}

type boundDialerContextValue struct {
	hints     *string
	localAddr string
}

func BoundDialerParamsToContext(ctx context.Context, hints *string, localAddr string) context.Context {
	return context.WithValue(ctx, boundDialerContextKey{}, boundDialerContextValue{hints, localAddr})
}

func BoundDialerParamsFromContext(ctx context.Context) (*string, string, bool) {
	val, ok := ctx.Value(boundDialerContextKey{}).(boundDialerContextValue)
	if !ok {
		return nil, "", false
	}
	return val.hints, val.localAddr, true
}

type filterContextKey struct{}

type filterContextParams struct {
	req      *http.Request
	username string
}

func FilterParamsFromContext(ctx context.Context) (*http.Request, string) {
	if params, ok := ctx.Value(filterContextKey{}).(filterContextParams); ok {
		return params.req, params.username
	}
	return nil, ""
}

func FilterParamsToContext(ctx context.Context, req *http.Request, username string) context.Context {
	return context.WithValue(ctx, filterContextKey{}, filterContextParams{req, username})
}

type origDstKey struct{}

func OrigDstFromContext(ctx context.Context) (string, bool) {
	orig, ok := ctx.Value(origDstKey{}).(string)
	return orig, ok
}

func OrigDstToContext(ctx context.Context, dst string) context.Context {
	return context.WithValue(ctx, origDstKey{}, dst)
}

type StopAddressIteration struct{}

func (_ StopAddressIteration) Error() string {
	return "address iteration halted"
}

var _ error = StopAddressIteration{}
