package guard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddleware_Privacy(t *testing.T) {
	rds := testRedis(t)
	g := NewGuardWithRedis(Config{
		Privacy: PrivacyConfig{
			Enabled:          true,
			SensitiveHeaders: []string{"Authorization", "Email"},
			TimezoneHeader:   "X-Timezone",
		},
	}, rds)

	mw := g.PrivacyMiddleware()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer my-secret-token")
	req.Header.Set("X-Timezone", "Asia/Tokyo")

	var capturedHeaders http.Header
	var capturedTZ string
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = GetSanitizedHeaders(r.Context())
		capturedTZ = GetTimezone(r.Context()).String()
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	if capturedHeaders == nil {
		t.Fatal("sanitized headers not stored in context")
	}

	if capturedHeaders.Get("Authorization") == "Bearer my-secret-token" {
		t.Error("Authorization was not sanitized")
	}

	if capturedTZ != "Asia/Tokyo" {
		t.Errorf("timezone = %s, want Asia/Tokyo", capturedTZ)
	}
}

func TestMiddleware_IPRisk_Allow(t *testing.T) {
	rds := testRedis(t)
	g := NewGuardWithRedis(Config{
		IPRisk: IPRiskConfig{
			Enabled:  true,
			MaxFails: 3,
		},
	}, rds)

	mw := g.IPRiskMiddleware()
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestMiddleware_RateLimit(t *testing.T) {
	rds := testRedis(t)
	g := NewGuardWithRedis(Config{
		Limiter: LimiterConfig{
			WindowSec:   60,
			GuestLimit:  2,
			UserLimit:   10,
			AdminBypass: true,
		},
	}, rds)

	mw := g.RateLimitMiddleware()

	do := func(t *testing.T, roleHeader, id string) int {
		t.Helper()
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set(roleHeader, id)
		rec := httptest.NewRecorder()
		mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rec, req)
		return rec.Code
	}

	t.Run("guest rate limited", func(t *testing.T) {
		code1 := do(t, "", "")
		code2 := do(t, "", "")
		code3 := do(t, "", "")
		if code1 != 200 || code2 != 200 {
			t.Error("first two requests should be allowed")
		}
		if code3 != 429 {
			t.Errorf("third request should be 429, got %d", code3)
		}
	})

	t.Run("user not rate limited within generous limit", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			if code := do(t, "X-User-Id", "test-user"); code == 429 {
				t.Errorf("user blocked on attempt %d", i+1)
				break
			}
		}
	})

	t.Run("admin bypass", func(t *testing.T) {
		for i := 0; i < 20; i++ {
			if code := do(t, "X-Admin", "admin-user"); code == 429 {
				t.Errorf("admin blocked on attempt %d", i+1)
				break
			}
		}
	})
}

func TestMiddleware_Full_Chain(t *testing.T) {
	rds := testRedis(t)
	g := NewGuardWithRedis(Config{
		Limiter: LimiterConfig{
			WindowSec:   60,
			GuestLimit:  5,
			UserLimit:   100,
			AdminBypass: true,
		},
		IPRisk: IPRiskConfig{
			Enabled:  true,
			MaxFails: 5,
		},
		Privacy: PrivacyConfig{
			Enabled:          true,
			SensitiveHeaders: []string{"Authorization"},
			TimezoneHeader:   "X-Timezone",
		},
	}, rds)

	mw := g.Middleware()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-User-Id", "user-1")
	req.Header.Set("X-Timezone", "America/New_York")
	req.Header.Set("Authorization", "Bearer test")

	rec := httptest.NewRecorder()
	var capturedRole Role
	var capturedTZ string
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRole = GetRole(r.Context())
		capturedTZ = GetTimezone(r.Context()).String()
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if capturedRole != RoleUser {
		t.Errorf("role = %v, want RoleUser", capturedRole)
	}
	if capturedTZ != "America/New_York" {
		t.Errorf("timezone = %s, want America/New_York", capturedTZ)
	}
}
