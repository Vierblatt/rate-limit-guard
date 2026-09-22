package guard

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Vierblatt/rate-limit-guard/limiter"
)

func TestContext_roundTrip(t *testing.T) {
	t.Run("role", func(t *testing.T) {
		ctx := WithRole(context.Background(), limiter.RoleAdmin)
		if got := GetRole(ctx); got != limiter.RoleAdmin {
			t.Errorf("GetRole = %v, want admin", got)
		}
	})

	t.Run("timezone", func(t *testing.T) {
		loc, err := time.LoadLocation("Asia/Tokyo")
		if err != nil {
			t.Fatal(err)
		}
		ctx := WithTimezone(context.Background(), loc)
		if got := GetTimezone(ctx); got != loc {
			t.Errorf("GetTimezone = %v, want %v", got, loc)
		}
	})

	t.Run("region", func(t *testing.T) {
		ctx := WithRegion(context.Background(), "10.0.0.1")
		if got := GetRegion(ctx); got != "10.0.0.1" {
			t.Errorf("GetRegion = %q, want 10.0.0.1", got)
		}
	})

	t.Run("country", func(t *testing.T) {
		ctx := WithCountry(context.Background(), "RU")
		if got := GetCountry(ctx); got != "RU" {
			t.Errorf("GetCountry = %q, want RU", got)
		}
	})

	t.Run("sanitized headers", func(t *testing.T) {
		h := http.Header{}
		h.Set("Authorization", "Bearer x")
		ctx := contextWithSanitizedHeaders(context.Background(), h)
		if got := GetSanitizedHeaders(ctx); got.Get("Authorization") != "Bearer x" {
			t.Errorf("GetSanitizedHeaders = %v, want the stored header", got)
		}
	})
}

func TestContext_defaultsWhenUnset(t *testing.T) {
	ctx := context.Background()

	if got := GetRole(ctx); got != limiter.RoleGuest {
		t.Errorf("GetRole on empty ctx = %v, want guest", got)
	}
	if got := GetTimezone(ctx); got != time.UTC {
		t.Errorf("GetTimezone on empty ctx = %v, want UTC", got)
	}
	if got := GetRegion(ctx); got != "" {
		t.Errorf("GetRegion on empty ctx = %q, want empty", got)
	}
	if got := GetCountry(ctx); got != "" {
		t.Errorf("GetCountry on empty ctx = %q, want empty", got)
	}
	if got := GetSanitizedHeaders(ctx); got != nil {
		t.Errorf("GetSanitizedHeaders on empty ctx = %v, want nil", got)
	}
}

func TestContext_wrongTypeIsIgnored(t *testing.T) {
	// A key collision with a foreign type must fall back to the default rather
	// than panicking.
	ctx := context.WithValue(context.Background(), ctxRoleKey, "not-a-role")

	if got := GetRole(ctx); got != limiter.RoleGuest {
		t.Errorf("GetRole with wrong type = %v, want guest", got)
	}
}
