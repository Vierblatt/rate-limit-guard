package iprisk

import (
	"net/http"
	"testing"
	"time"
)

func TestRiskLevelString(t *testing.T) {
	tests := map[RiskLevel]string{
		RiskLow:      "low",
		RiskMid:      "mid",
		RiskHigh:     "high",
		RiskLevel(9): "unknown",
	}
	for level, want := range tests {
		if got := level.String(); got != want {
			t.Errorf("RiskLevel(%d).String() = %q, want %q", int(level), got, want)
		}
	}
}

func TestEvaluate_normalizesInput(t *testing.T) {
	risk := New(Config{Enabled: true, HighRiskCountries: []string{"RU", "UA"}})

	tests := []struct {
		name    string
		country string
		want    RiskLevel
	}{
		{"lowercase", "ru", RiskHigh},
		{"mixed case", "Ru", RiskHigh},
		{"padded", "  UA  ", RiskHigh},
		{"unknown sentinel XX is never high risk", unknownCountry, RiskLow},
		{"not in list", "US", RiskLow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := risk.Evaluate(tt.country); got != tt.want {
				t.Errorf("Evaluate(%q) = %v, want %v", tt.country, got, tt.want)
			}
		})
	}
}

func TestEvaluate_XXIsNotHighRiskEvenIfConfigured(t *testing.T) {
	// A CDN sends XX when it cannot geolocate a client. Treating that as
	// high-risk would silently throttle every unattributable request.
	risk := New(Config{Enabled: true, HighRiskCountries: []string{"XX", "RU"}})

	if got := risk.Evaluate("XX"); got != RiskLow {
		t.Errorf("Evaluate(XX) = %v, want RiskLow", got)
	}
	if got := risk.Evaluate("RU"); got != RiskHigh {
		t.Errorf("Evaluate(RU) = %v, want RiskHigh", got)
	}
}

func TestCountryFrom(t *testing.T) {
	risk := New(Config{Enabled: true, CountryHeader: "CF-IPCountry"})

	req := http.Header{}
	req.Set("CF-IPCountry", "ru")

	if got := risk.CountryFrom(req); got != "RU" {
		t.Errorf("CountryFrom = %q, want RU (upper-cased and trimmed)", got)
	}

	t.Run("missing header", func(t *testing.T) {
		if got := risk.CountryFrom(http.Header{}); got != "" {
			t.Errorf("CountryFrom = %q, want empty", got)
		}
	})

	t.Run("disabled", func(t *testing.T) {
		off := New(Config{Enabled: false, CountryHeader: "CF-IPCountry"})
		h := http.Header{}
		h.Set("CF-IPCountry", "RU")
		if got := off.CountryFrom(h); got != "" {
			t.Errorf("CountryFrom when disabled = %q, want empty", got)
		}
	})

	t.Run("no header configured", func(t *testing.T) {
		none := New(Config{Enabled: true})
		h := http.Header{}
		h.Set("CF-IPCountry", "RU")
		if got := none.CountryFrom(h); got != "" {
			t.Errorf("CountryFrom without header config = %q, want empty", got)
		}
	})
}

func TestQuota(t *testing.T) {
	risk := New(Config{
		Enabled:           true,
		HighRiskCountries: []string{"RU"},
		RiskQuotaRatio:    0.2,
	})

	tests := []struct {
		name    string
		country string
		base    int
		want    int
	}{
		{"low risk unchanged", "US", 100, 100},
		{"unknown country unchanged", "", 100, 100},
		{"high risk tightened", "RU", 100, 20},
		{"high risk rounds down", "RU", 33, 6},
		{"exempt role stays exempt", "RU", 0, 0},
		{"negative base stays exempt", "RU", -5, -5},
		{"ratio floor of 1", "RU", 4, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := risk.Quota(tt.country, tt.base); got != tt.want {
				t.Errorf("Quota(%q, %d) = %d, want %d", tt.country, tt.base, got, tt.want)
			}
		})
	}
}

func TestQuota_invalidRatioIsIgnored(t *testing.T) {
	for _, ratio := range []float64{0, -1, 1.5} {
		risk := New(Config{
			Enabled:           true,
			HighRiskCountries: []string{"RU"},
			RiskQuotaRatio:    ratio,
		})
		// An out-of-range ratio must not drop traffic to nonsense; it falls
		// back to the base quota.
		if got := risk.Quota("RU", 100); got != 100 {
			t.Errorf("ratio %v: Quota = %d, want 100", ratio, got)
		}
	}
}

func TestIsWhitelisted_emptyList(t *testing.T) {
	risk := New(Config{Enabled: true})
	if risk.IsWhitelisted("1.2.3.4") {
		t.Error("nothing should be whitelisted with an empty list")
	}
}

func TestBlock_expiry(t *testing.T) {
	rds := blTestRedis(t)
	cleanBlacklist(t, rds)

	bl := NewBlacklist(rds, Config{BlacklistTTL: 10, MaxFails: 3})
	if err := bl.Block("10.1.1.1", time.Second); err != nil {
		t.Fatal(err)
	}

	blocked, err := bl.IsBlocked("10.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if !blocked {
		t.Error("should be blocked immediately after Block")
	}
}

func TestSize(t *testing.T) {
	rds := blTestRedis(t)
	cleanBlacklist(t, rds)

	bl := NewBlacklist(rds, Config{BlacklistTTL: 10, MaxFails: 1})

	size, err := bl.Size()
	if err != nil {
		t.Fatal(err)
	}
	if size != 0 {
		t.Errorf("Size() = %d, want 0 for an empty blacklist", size)
	}

	for _, ip := range []string{"10.2.0.1", "10.2.0.2", "10.2.0.3"} {
		if _, err := bl.RecordFail(ip); err != nil {
			t.Fatal(err)
		}
	}

	size, err = bl.Size()
	if err != nil {
		t.Fatal(err)
	}
	if size != 3 {
		t.Errorf("Size() = %d, want 3", size)
	}

	if err := bl.Remove("10.2.0.2"); err != nil {
		t.Fatal(err)
	}
	size, err = bl.Size()
	if err != nil {
		t.Fatal(err)
	}
	if size != 2 {
		t.Errorf("Size() after Remove = %d, want 2", size)
	}
}

func TestBlacklist_errorsWhenRedisDown(t *testing.T) {
	rds := deadRedis(t)
	bl := NewBlacklist(rds, Config{BlacklistTTL: 1, MaxFails: 3})

	if _, err := bl.IsBlocked("10.0.0.9"); err == nil {
		t.Error("IsBlocked should error when Redis is unreachable")
	}
	if _, err := bl.RecordFail("10.0.0.9"); err == nil {
		t.Error("RecordFail should error when Redis is unreachable")
	}
	if _, err := bl.Size(); err == nil {
		t.Error("Size should error when Redis is unreachable")
	}
	if err := bl.Remove("10.0.0.9"); err == nil {
		t.Error("Remove should error when Redis is unreachable")
	}
	if err := bl.Block("10.0.0.9", time.Minute); err == nil {
		t.Error("Block should error when Redis is unreachable")
	}
}
