package guard

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Vierblatt/rate-limit-guard/iprisk"
	"github.com/Vierblatt/rate-limit-guard/limiter"
)

func TestMustLoadConfig_readsShippedExample(t *testing.T) {
	// The example config in the repo root must stay loadable; it is what users
	// copy when wiring the middleware into a gateway.
	cfg := MustLoadConfig("config.yaml")

	if cfg.RedisAddr == "" {
		t.Error("RedisAddr should be populated")
	}
	if cfg.Limiter.GuestLimit <= 0 {
		t.Errorf("GuestLimit = %d, want > 0", cfg.Limiter.GuestLimit)
	}
	if cfg.Limiter.UserLimit <= 0 {
		t.Errorf("UserLimit = %d, want > 0", cfg.Limiter.UserLimit)
	}
	if len(cfg.IPRisk.HighRiskCountries) == 0 {
		t.Error("HighRiskCountries should be populated")
	}
	if cfg.IPRisk.RiskQuotaRatio <= 0 || cfg.IPRisk.RiskQuotaRatio > 1 {
		t.Errorf("RiskQuotaRatio = %v, want a ratio in (0,1]", cfg.IPRisk.RiskQuotaRatio)
	}
	if cfg.IPRisk.CountryHeader == "" {
		t.Error("CountryHeader should be populated")
	}
	if len(cfg.Privacy.SensitiveHeaders) == 0 {
		t.Error("SensitiveHeaders should be populated")
	}
}

func TestMustLoadConfig_fromTempFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "guard.yaml")

	body := []byte("RedisAddr: 127.0.0.1:6380\n" +
		"Limiter:\n  WindowSec: 30\n  GuestLimit: 5\n  UserLimit: 50\n" +
		"IPRisk:\n  CountryHeader: X-Country\n  RiskQuotaRatio: 0.5\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := MustLoadConfig(path)
	if cfg.RedisAddr != "127.0.0.1:6380" {
		t.Errorf("RedisAddr = %q", cfg.RedisAddr)
	}
	if cfg.Limiter.WindowSec != 30 {
		t.Errorf("WindowSec = %d, want 30", cfg.Limiter.WindowSec)
	}
	if cfg.IPRisk.CountryHeader != "X-Country" {
		t.Errorf("CountryHeader = %q, want X-Country", cfg.IPRisk.CountryHeader)
	}
	if cfg.IPRisk.RiskQuotaRatio != 0.5 {
		t.Errorf("RiskQuotaRatio = %v, want 0.5", cfg.IPRisk.RiskQuotaRatio)
	}
}

func TestNewGuard_connectsAndAppliesDefaults(t *testing.T) {
	mr := newMiniRedis(t)

	g := NewGuard(Config{
		RedisAddr: mr.Addr(),
		Limiter:   limiter.Config{WindowSec: 60, GuestLimit: 5, UserLimit: 20},
	})

	if g.Redis() == nil {
		t.Fatal("Redis() should be populated")
	}

	cfg := g.Config()
	if cfg.IPRisk.CountryHeader != "CF-IPCountry" {
		t.Errorf("CountryHeader = %q, want the defaulted value", cfg.IPRisk.CountryHeader)
	}
	if cfg.IPRisk.RiskQuotaRatio != 0.2 {
		t.Errorf("RiskQuotaRatio = %v, want 0.2", cfg.IPRisk.RiskQuotaRatio)
	}
}

func TestEnforceRateLimit_redisFailureIs500(t *testing.T) {
	rds := deadRedis(t)
	g := NewGuardWithRedis(Config{
		Limiter: limiter.Config{WindowSec: 60, GuestLimit: 10, UserLimit: 10},
		IPRisk:  iprisk.Config{Enabled: false},
	}, rds)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.90:1234"
	rec := serve(g.RateLimitMiddleware(), req, okHandler(t, nil))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 when Redis is unreachable", rec.Code)
	}
}

func TestIPRiskMiddleware_redisFailureIs500(t *testing.T) {
	rds := deadRedis(t)
	g := NewGuardWithRedis(Config{
		IPRisk: iprisk.Config{Enabled: true},
	}, rds)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.91:1234"
	rec := serve(g.IPRiskMiddleware(), req, okHandler(t, nil))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 when Redis is unreachable", rec.Code)
	}
}
