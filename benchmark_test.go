package guard

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Vierblatt/rate-limit-guard/iprisk"
	"github.com/Vierblatt/rate-limit-guard/limiter"
	"github.com/Vierblatt/rate-limit-guard/privacy"
)

func BenchmarkSlidingWindowLimiter(b *testing.B) {
	rds := testRedis(b)

	cfg := limiter.Config{
		WindowSec: 60, GuestLimit: 10000, UserLimit: 10000, AdminBypass: true,
	}
	lim := limiter.New(rds, cfg)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			lim.Allow(limiter.RoleGuest, "bench-guest")
		}
	})
}

func BenchmarkFullMiddleware(b *testing.B) {
	rds := testRedis(b)

	g := NewGuardWithRedis(Config{
		Limiter: limiter.Config{
			WindowSec: 60, GuestLimit: 100000, UserLimit: 100000, AdminBypass: true,
		},
		IPRisk:  iprisk.Config{Enabled: true, MaxFails: 10, BlacklistTTL: 1},
		Privacy: privacy.Config{Enabled: true, SensitiveHeaders: []string{"Authorization", "Email"}, TimezoneHeader: "X-Timezone"},
	}, rds)

	mw := g.Middleware()
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	server := httptest.NewServer(handler)
	defer server.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req, _ := http.NewRequest("GET", server.URL, nil)
			req.Header.Set("X-User-Id", "bench-user")
			req.Header.Set("X-Timezone", "Asia/Shanghai")
			req.Header.Set("Authorization", "Bearer test-token")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				b.Fatal(err)
			}
			resp.Body.Close()
		}
	})
}

func BenchmarkMiddlewares(b *testing.B) {
	rds := testRedis(b)

	g := NewGuardWithRedis(Config{
		Limiter: limiter.Config{
			WindowSec: 60, GuestLimit: 100000, UserLimit: 100000, AdminBypass: true,
		},
		IPRisk:  iprisk.Config{Enabled: true, MaxFails: 10, BlacklistTTL: 1},
		Privacy: privacy.Config{Enabled: true, SensitiveHeaders: []string{"Authorization", "Email"}, TimezoneHeader: "X-Timezone"},
	}, rds)

	benchmarks := []struct {
		name string
		mw   func(http.HandlerFunc) http.HandlerFunc
	}{
		{"Privacy", g.PrivacyMiddleware()},
		{"IPRisk", g.IPRiskMiddleware()},
		{"RateLimit", g.RateLimitMiddleware()},
		{"All", g.Middleware()},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			handler := bm.mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			server := httptest.NewServer(handler)
			defer server.Close()

			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					req, _ := http.NewRequest("GET", server.URL, nil)
					req.Header.Set("X-User-Id", "bench-user")
					req.Header.Set("X-Timezone", "Asia/Shanghai")
					resp, err := http.DefaultClient.Do(req)
					if err != nil {
						b.Fatal(err)
					}
					resp.Body.Close()
				}
			})
		})
	}
}
