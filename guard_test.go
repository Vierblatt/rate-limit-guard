package guard

import (
	"testing"

	"github.com/Vierblatt/rate-limit-guard/iprisk"
	"github.com/Vierblatt/rate-limit-guard/limiter"
)

func TestApplyDefaults(t *testing.T) {
	t.Run("empty config gets defaults", func(t *testing.T) {
		var cfg Config
		applyDefaults(&cfg)

		if len(cfg.Privacy.SensitiveHeaders) == 0 {
			t.Error("SensitiveHeaders should be defaulted")
		}
		if len(cfg.IPRisk.HighRiskCountries) == 0 {
			t.Error("HighRiskCountries should be defaulted")
		}
		if cfg.IPRisk.BlacklistTTL != 10 {
			t.Errorf("BlacklistTTL = %d, want 10", cfg.IPRisk.BlacklistTTL)
		}
		if cfg.IPRisk.MaxFails != 3 {
			t.Errorf("MaxFails = %d, want 3", cfg.IPRisk.MaxFails)
		}
		if cfg.IPRisk.RiskQuotaRatio != 0.2 {
			t.Errorf("RiskQuotaRatio = %v, want 0.2", cfg.IPRisk.RiskQuotaRatio)
		}
		if cfg.IPRisk.CountryHeader != "CF-IPCountry" {
			t.Errorf("CountryHeader = %q, want CF-IPCountry", cfg.IPRisk.CountryHeader)
		}
	})

	t.Run("explicit values are preserved", func(t *testing.T) {
		cfg := Config{
			IPRisk: iprisk.Config{
				BlacklistTTL:   15,
				MaxFails:       7,
				RiskQuotaRatio: 0.5,
				CountryHeader:  "X-Country",
			},
		}
		applyDefaults(&cfg)

		if cfg.IPRisk.BlacklistTTL != 15 {
			t.Errorf("BlacklistTTL = %d, want the configured 15", cfg.IPRisk.BlacklistTTL)
		}
		if cfg.IPRisk.MaxFails != 7 {
			t.Errorf("MaxFails = %d, want the configured 7", cfg.IPRisk.MaxFails)
		}
		if cfg.IPRisk.RiskQuotaRatio != 0.5 {
			t.Errorf("RiskQuotaRatio = %v, want the configured 0.5", cfg.IPRisk.RiskQuotaRatio)
		}
		if cfg.IPRisk.CountryHeader != "X-Country" {
			t.Errorf("CountryHeader = %q, want the configured X-Country", cfg.IPRisk.CountryHeader)
		}
	})

	t.Run("out-of-range ratio falls back", func(t *testing.T) {
		for _, ratio := range []float64{-1, 0, 1.5} {
			cfg := Config{}
			cfg.IPRisk.RiskQuotaRatio = ratio
			applyDefaults(&cfg)

			if cfg.IPRisk.RiskQuotaRatio != 0.2 {
				t.Errorf("ratio %v: RiskQuotaRatio = %v, want 0.2", ratio, cfg.IPRisk.RiskQuotaRatio)
			}
		}
	})

	t.Run("ratio of exactly 1 is kept", func(t *testing.T) {
		cfg := Config{}
		cfg.IPRisk.RiskQuotaRatio = 1
		applyDefaults(&cfg)

		if cfg.IPRisk.RiskQuotaRatio != 1 {
			t.Errorf("RiskQuotaRatio = %v, want 1", cfg.IPRisk.RiskQuotaRatio)
		}
	})
}

func TestGuard_accessors(t *testing.T) {
	rds := testRedis(t)
	g := NewGuardWithRedis(Config{
		Limiter: limiter.Config{WindowSec: 60, GuestLimit: 30, UserLimit: 100, AdminBypass: true},
	}, rds)

	if g.Redis() != rds {
		t.Error("Redis() should return the injected client")
	}
	if g.Metrics() == nil {
		t.Error("Metrics() should never be nil")
	}

	// applyDefaults runs on construction, so the accessor must expose the
	// effective config rather than the raw input.
	if got := g.Config().IPRisk.CountryHeader; got != "CF-IPCountry" {
		t.Errorf("Config().IPRisk.CountryHeader = %q, want the defaulted value", got)
	}
}

func TestNewGuardWithRedis_defaultsApplied(t *testing.T) {
	rds := testRedis(t)
	g := NewGuardWithRedis(Config{}, rds)

	cfg := g.Config()
	if cfg.IPRisk.RiskQuotaRatio != 0.2 {
		t.Errorf("RiskQuotaRatio = %v, want 0.2", cfg.IPRisk.RiskQuotaRatio)
	}
	if len(cfg.IPRisk.HighRiskCountries) == 0 {
		t.Error("HighRiskCountries should be defaulted")
	}
}
