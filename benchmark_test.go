package guard

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/Vierblatt/rate-limit-guard/iprisk"
	"github.com/Vierblatt/rate-limit-guard/limiter"
	"github.com/Vierblatt/rate-limit-guard/privacy"
	"github.com/alicebob/miniredis/v2"
	"github.com/zeromicro/go-zero/core/stores/redis"
)

func benchRedis(b testing.TB) *redis.Redis {
	b.Helper()
	if addr := os.Getenv("BENCHMARK_REDIS_ADDR"); addr != "" {
		rds, err := redis.NewRedis(redis.RedisConf{Host: addr, Type: "node"})
		if err != nil {
			b.Fatalf("connect to %s: %v", addr, err)
		}
		return rds
	}

	mr, err := miniredis.Run()
	if err != nil {
		b.Fatalf("miniredis.Run: %v", err)
	}
	b.Cleanup(mr.Close)

	rds, err := redis.NewRedis(redis.RedisConf{Host: mr.Addr(), Type: "node"})
	if err != nil {
		b.Fatalf("redis.NewRedis: %v", err)
	}
	return rds
}

func BenchmarkSlidingWindowLimiter(b *testing.B) {
	rds := benchRedis(b)

	cfg := limiter.Config{WindowSec: 60, GuestLimit: 10000, UserLimit: 10000}
	lim := limiter.New(rds, cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lim.Allow(limiter.RoleGuest, "bench-guest")
	}
}

func BenchmarkSlidingWindowLimiter_Parallel(b *testing.B) {
	rds := benchRedis(b)

	cfg := limiter.Config{WindowSec: 60, GuestLimit: 100000, UserLimit: 100000}
	lim := limiter.New(rds, cfg)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			lim.Allow(limiter.RoleGuest, "bench-parallel")
		}
	})
}

func BenchmarkMiddlewares(b *testing.B) {
	rds := benchRedis(b)

	g := NewGuardWithRedis(Config{
		Limiter: limiter.Config{WindowSec: 60, GuestLimit: 100000, UserLimit: 100000, AdminBypass: true},
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

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					req := httptest.NewRequest("GET", "/", nil)
					req.Header.Set("X-User-Id", "bench-user")
					req.Header.Set("X-Timezone", "Asia/Shanghai")
					req.Header.Set("Authorization", "Bearer test-token")
					handler.ServeHTTP(httptest.NewRecorder(), req)
				}
			})
		})
	}
}
