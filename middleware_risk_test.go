package guard

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Vierblatt/rate-limit-guard/iprisk"
	"github.com/Vierblatt/rate-limit-guard/limiter"
	"github.com/Vierblatt/rate-limit-guard/privacy"
)

func okHandler(t *testing.T, onCall func(*http.Request)) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if onCall != nil {
			onCall(r)
		}
		w.WriteHeader(http.StatusOK)
	}
}

func serve(mw func(http.HandlerFunc) http.HandlerFunc, req *http.Request, next http.HandlerFunc) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	mw(next).ServeHTTP(rec, req)
	return rec
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		want       string
	}{
		{
			name:       "X-Forwarded-For wins",
			remoteAddr: "10.0.0.9:1234",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.7"},
			want:       "203.0.113.7",
		},
		{
			name:       "first entry of a proxy chain",
			remoteAddr: "10.0.0.9:1234",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.7, 10.0.0.1, 10.0.0.2"},
			want:       "203.0.113.7",
		},
		{
			name:       "X-Forwarded-For is trimmed",
			remoteAddr: "10.0.0.9:1234",
			headers:    map[string]string{"X-Forwarded-For": "  203.0.113.7  "},
			want:       "203.0.113.7",
		},
		{
			name:       "X-Real-IP when no XFF",
			remoteAddr: "10.0.0.9:1234",
			headers:    map[string]string{"X-Real-IP": "198.51.100.5"},
			want:       "198.51.100.5",
		},
		{
			name:       "falls back to RemoteAddr",
			remoteAddr: "192.0.2.10:5678",
			want:       "192.0.2.10",
		},
		{
			name:       "RemoteAddr without a port",
			remoteAddr: "192.0.2.11",
			want:       "192.0.2.11",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			if got := extractIP(req); got != tt.want {
				t.Errorf("extractIP = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetectRole(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    limiter.Role
	}{
		{"no headers is a guest", nil, limiter.RoleGuest},
		{"X-User-Id is a user", map[string]string{"X-User-Id": "u1"}, limiter.RoleUser},
		{"X-Admin is an admin", map[string]string{"X-Admin": "a1"}, limiter.RoleAdmin},
		{
			"admin wins over user",
			map[string]string{"X-Admin": "a1", "X-User-Id": "u1"},
			limiter.RoleAdmin,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			if got := detectRole(req); got != tt.want {
				t.Errorf("detectRole = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolveID(t *testing.T) {
	t.Run("admin uses the admin header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Admin", "admin-42")
		if got := resolveID(req, limiter.RoleAdmin); got != "admin-42" {
			t.Errorf("resolveID = %q, want admin-42", got)
		}
	})

	t.Run("user uses the user header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-User-Id", "user-7")
		if got := resolveID(req, limiter.RoleUser); got != "user-7" {
			t.Errorf("resolveID = %q, want user-7", got)
		}
	})

	t.Run("guest uses the client IP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "203.0.113.9:1234"
		if got := resolveID(req, limiter.RoleGuest); got != "203.0.113.9" {
			t.Errorf("resolveID = %q, want 203.0.113.9", got)
		}
	})
}

func TestPrivacyMiddleware_timezoneAndSanitize(t *testing.T) {
	rds := testRedis(t)
	g := NewGuardWithRedis(Config{
		Privacy: privacy.Config{
			Enabled:          true,
			SensitiveHeaders: []string{"Authorization"},
			TimezoneHeader:   "X-Timezone",
		},
	}, rds)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Timezone", "America/New_York")
	req.Header.Set("Authorization", "Bearer super-secret-token")

	var gotTZ string
	var gotAuth string
	rec := serve(g.PrivacyMiddleware(), req, okHandler(t, func(r *http.Request) {
		gotTZ = GetTimezone(r.Context()).String()
		gotAuth = GetSanitizedHeaders(r.Context()).Get("Authorization")
	}))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if gotTZ != "America/New_York" {
		t.Errorf("timezone = %q, want America/New_York", gotTZ)
	}
	if gotAuth == "Bearer super-secret-token" {
		t.Error("Authorization should have been sanitized")
	}
}

func TestPrivacyMiddleware_disabledSkipsSanitizing(t *testing.T) {
	rds := testRedis(t)
	g := NewGuardWithRedis(Config{
		Privacy: privacy.Config{Enabled: false, TimezoneHeader: "X-Timezone"},
	}, rds)

	var headers http.Header
	serve(g.PrivacyMiddleware(), httptest.NewRequest("GET", "/", nil), okHandler(t, func(r *http.Request) {
		headers = GetSanitizedHeaders(r.Context())
	}))

	if headers != nil {
		t.Error("sanitized headers should not be stored when privacy is disabled")
	}
}

func TestIPRiskMiddleware_blocksBlacklistedIP(t *testing.T) {
	rds := testRedis(t)
	g := NewGuardWithRedis(Config{
		IPRisk: iprisk.Config{Enabled: true, MaxFails: 1, BlacklistTTL: 10},
	}, rds)

	// MaxFails=1 means the first recorded failure blacklists the IP.
	if _, err := g.blacklist.RecordFail("203.0.113.50"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.50:1234"

	rec := serve(g.IPRiskMiddleware(), req, okHandler(t, nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestIPRiskMiddleware_disabledLetsTrafficThrough(t *testing.T) {
	rds := testRedis(t)
	g := NewGuardWithRedis(Config{
		IPRisk: iprisk.Config{Enabled: false, MaxFails: 1, BlacklistTTL: 10},
	}, rds)

	if _, err := g.blacklist.RecordFail("203.0.113.51"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.51:1234"

	rec := serve(g.IPRiskMiddleware(), req, okHandler(t, nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 when IP risk control is disabled", rec.Code)
	}
}

func TestIPRiskMiddleware_whitelistedIPBypassesBlacklist(t *testing.T) {
	rds := testRedis(t)
	g := NewGuardWithRedis(Config{
		IPRisk: iprisk.Config{
			Enabled: true, MaxFails: 1, BlacklistTTL: 10,
			Whitelist: []string{"203.0.113.52"},
		},
	}, rds)

	if _, err := g.blacklist.RecordFail("203.0.113.52"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.52:1234"

	rec := serve(g.IPRiskMiddleware(), req, okHandler(t, nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for a whitelisted IP", rec.Code)
	}
}

func TestIPRiskMiddleware_exposesCountry(t *testing.T) {
	rds := testRedis(t)
	g := NewGuardWithRedis(Config{
		IPRisk: iprisk.Config{Enabled: true, CountryHeader: "CF-IPCountry"},
	}, rds)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.53:1234"
	req.Header.Set("CF-IPCountry", "ru")

	var country string
	serve(g.IPRiskMiddleware(), req, okHandler(t, func(r *http.Request) {
		country = GetCountry(r.Context())
	}))

	if country != "RU" {
		t.Errorf("country = %q, want RU", country)
	}
}

func TestRateLimitMiddleware_highRiskCountryGetsTighterQuota(t *testing.T) {
	rds := testRedis(t)
	g := NewGuardWithRedis(Config{
		Limiter: limiter.Config{WindowSec: 60, GuestLimit: 10, UserLimit: 100, AdminBypass: true},
		IPRisk: iprisk.Config{
			Enabled:           true,
			HighRiskCountries: []string{"RU"},
			RiskQuotaRatio:    0.2,
			CountryHeader:     "CF-IPCountry",
		},
	}, rds)

	mw := g.RateLimitMiddleware()

	call := func(ip, country string) int {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = ip + ":1234"
		if country != "" {
			req.Header.Set("CF-IPCountry", country)
		}
		return serve(mw, req, okHandler(t, nil)).Code
	}

	// Normal guests get 10 requests per window.
	t.Run("normal country", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			if code := call("198.51.100.10", "US"); code != http.StatusOK {
				t.Fatalf("request %d: status = %d, want 200", i+1, code)
			}
		}
		if code := call("198.51.100.10", "US"); code != http.StatusTooManyRequests {
			t.Errorf("11th request: status = %d, want 429", code)
		}
	})

	// A high-risk country gets 20% of that, i.e. 2 requests.
	t.Run("high risk country", func(t *testing.T) {
		for i := 0; i < 2; i++ {
			if code := call("198.51.100.11", "RU"); code != http.StatusOK {
				t.Fatalf("request %d: status = %d, want 200", i+1, code)
			}
		}
		if code := call("198.51.100.11", "RU"); code != http.StatusTooManyRequests {
			t.Errorf("3rd request: status = %d, want 429", code)
		}
	})
}

func TestRateLimitMiddleware_IPRiskDisabledKeepsFullQuota(t *testing.T) {
	rds := testRedis(t)
	g := NewGuardWithRedis(Config{
		Limiter: limiter.Config{WindowSec: 60, GuestLimit: 3, UserLimit: 100},
		IPRisk:  iprisk.Config{Enabled: false},
	}, rds)

	mw := g.RateLimitMiddleware()

	// Even with a high-risk country header, a disabled risk module must not
	// tighten anything.
	call := func() int {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "198.51.100.20:1234"
		req.Header.Set("CF-IPCountry", "RU")
		return serve(mw, req, okHandler(t, nil)).Code
	}

	for i := 0; i < 3; i++ {
		if code := call(); code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i+1, code)
		}
	}
	if code := call(); code != http.StatusTooManyRequests {
		t.Errorf("4th request: status = %d, want 429", code)
	}
}

func TestFullMiddleware_whitelistedIPIsExemptFromRateLimit(t *testing.T) {
	rds := testRedis(t)
	g := NewGuardWithRedis(Config{
		Limiter: limiter.Config{WindowSec: 60, GuestLimit: 1, UserLimit: 1},
		IPRisk: iprisk.Config{
			Enabled: true, CountryHeader: "CF-IPCountry",
			Whitelist: []string{"203.0.113.60"},
		},
	}, rds)

	mw := g.Middleware()
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "203.0.113.60:1234"
		if code := serve(mw, req, okHandler(t, nil)).Code; code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200 for a whitelisted IP", i+1, code)
		}
	}
}

func TestFullMiddleware_setsAllContextValues(t *testing.T) {
	rds := testRedis(t)
	g := NewGuardWithRedis(Config{
		Limiter: limiter.Config{WindowSec: 60, GuestLimit: 100, UserLimit: 100},
		IPRisk:  iprisk.Config{Enabled: true, CountryHeader: "CF-IPCountry"},
		Privacy: privacy.Config{
			Enabled: true, SensitiveHeaders: []string{"Authorization"},
			TimezoneHeader: "X-Timezone",
		},
	}, rds)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.70:1234"
	req.Header.Set("X-User-Id", "user-1")
	req.Header.Set("CF-IPCountry", "cn")
	req.Header.Set("X-Timezone", "Asia/Shanghai")
	req.Header.Set("Authorization", "Bearer secret-token-value")

	var (
		role    limiter.Role
		region  string
		country string
		tz      string
		auth    string
	)
	rec := serve(g.Middleware(), req, okHandler(t, func(r *http.Request) {
		ctx := r.Context()
		role = GetRole(ctx)
		region = GetRegion(ctx)
		country = GetCountry(ctx)
		tz = GetTimezone(ctx).String()
		auth = GetSanitizedHeaders(ctx).Get("Authorization")
	}))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if role != limiter.RoleUser {
		t.Errorf("role = %v, want user", role)
	}
	if region != "203.0.113.70" {
		t.Errorf("region = %q, want 203.0.113.70", region)
	}
	if country != "CN" {
		t.Errorf("country = %q, want CN", country)
	}
	if tz != "Asia/Shanghai" {
		t.Errorf("timezone = %q, want Asia/Shanghai", tz)
	}
	if auth == "Bearer secret-token-value" {
		t.Error("Authorization should have been sanitized")
	}
}

func TestFullMiddleware_rateLimitRejectionFeedsBlacklist(t *testing.T) {
	rds := testRedis(t)
	g := NewGuardWithRedis(Config{
		Limiter: limiter.Config{WindowSec: 60, GuestLimit: 1, UserLimit: 1},
		IPRisk:  iprisk.Config{Enabled: true, MaxFails: 1, BlacklistTTL: 10},
	}, rds)

	mw := g.Middleware()
	call := func() int {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "203.0.113.80:1234"
		return serve(mw, req, okHandler(t, nil)).Code
	}

	if code := call(); code != http.StatusOK {
		t.Fatalf("first request: status = %d, want 200", code)
	}
	// Second request trips the limit and records a failure, which with
	// MaxFails=1 immediately blacklists the IP.
	if code := call(); code != http.StatusTooManyRequests {
		t.Fatalf("second request: status = %d, want 429", code)
	}
	// Third request is rejected by the blacklist before reaching the limiter.
	if code := call(); code != http.StatusForbidden {
		t.Errorf("third request: status = %d, want 403", code)
	}
}
