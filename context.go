package guard

import (
	"context"
	"net/http"
	"time"

	"github.com/Vierblatt/rate-limit-guard/limiter"
)

type ctxKey int

const (
	ctxRoleKey ctxKey = iota
	ctxTimezoneKey
	ctxRegionKey
	ctxSanitizedHeadersKey
)

func WithRole(ctx context.Context, role limiter.Role) context.Context {
	return context.WithValue(ctx, ctxRoleKey, role)
}

func GetRole(ctx context.Context) limiter.Role {
	if v, ok := ctx.Value(ctxRoleKey).(limiter.Role); ok {
		return v
	}
	return limiter.RoleGuest
}

func WithTimezone(ctx context.Context, loc *time.Location) context.Context {
	return context.WithValue(ctx, ctxTimezoneKey, loc)
}

func GetTimezone(ctx context.Context) *time.Location {
	if v, ok := ctx.Value(ctxTimezoneKey).(*time.Location); ok {
		return v
	}
	return time.UTC
}

func WithRegion(ctx context.Context, region string) context.Context {
	return context.WithValue(ctx, ctxRegionKey, region)
}

func GetRegion(ctx context.Context) string {
	if v, ok := ctx.Value(ctxRegionKey).(string); ok {
		return v
	}
	return ""
}

func contextWithSanitizedHeaders(ctx context.Context, h http.Header) context.Context {
	return context.WithValue(ctx, ctxSanitizedHeadersKey, h)
}

func GetSanitizedHeaders(ctx context.Context) http.Header {
	if v, ok := ctx.Value(ctxSanitizedHeadersKey).(http.Header); ok {
		return v
	}
	return nil
}
