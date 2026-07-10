package iprisk

import "testing"

func TestEvaluate(t *testing.T) {
	cfg := Config{
		Enabled:           true,
		HighRiskCountries: []string{"RU", "UA", "NG"},
	}
	risk := New(cfg)

	tests := []struct {
		country string
		want    RiskLevel
	}{
		{"RU", RiskHigh},
		{"UA", RiskHigh},
		{"NG", RiskHigh},
		{"US", RiskLow},
		{"CN", RiskLow},
		{"", RiskLow},
	}

	for _, tt := range tests {
		got := risk.Evaluate(tt.country)
		if got != tt.want {
			t.Errorf("Evaluate(%q) = %v, want %v", tt.country, got, tt.want)
		}
	}
}

func TestEvaluate_disabled(t *testing.T) {
	cfg := Config{Enabled: false, HighRiskCountries: []string{"RU"}}
	risk := New(cfg)

	if got := risk.Evaluate("RU"); got != RiskLow {
		t.Errorf("Evaluate disabled = %v, want RiskLow", got)
	}
}

func TestWhitelist(t *testing.T) {
	cfg := Config{Enabled: true, Whitelist: []string{"10.0.0.1", "192.168.1.1"}}
	risk := New(cfg)

	if !risk.IsWhitelisted("10.0.0.1") {
		t.Error("10.0.0.1 should be whitelisted")
	}
	if risk.IsWhitelisted("8.8.8.8") {
		t.Error("8.8.8.8 should not be whitelisted")
	}
}

func TestEvaluate_emptyConfig(t *testing.T) {
	risk := New(Config{Enabled: true})
	if got := risk.Evaluate("RU"); got != RiskLow {
		t.Errorf("empty config = %v, want RiskLow", got)
	}
}
