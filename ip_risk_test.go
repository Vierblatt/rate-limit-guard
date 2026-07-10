package guard

import "testing"

func TestIPRiskEvaluate(t *testing.T) {
	cfg := IPRiskConfig{
		Enabled:           true,
		HighRiskCountries: []string{"RU", "UA", "NG"},
	}
	risk := NewIPRisk(cfg)

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

func TestIPRiskDisabled(t *testing.T) {
	cfg := IPRiskConfig{
		Enabled:           false,
		HighRiskCountries: []string{"RU"},
	}
	risk := NewIPRisk(cfg)

	if got := risk.Evaluate("RU"); got != RiskLow {
		t.Errorf("Evaluate with disabled = %v, want RiskLow", got)
	}
}

func TestIPRiskWhitelist(t *testing.T) {
	cfg := IPRiskConfig{
		Enabled:   true,
		Whitelist: []string{"10.0.0.1", "192.168.1.1"},
	}
	risk := NewIPRisk(cfg)

	if !risk.IsWhitelisted("10.0.0.1") {
		t.Error("10.0.0.1 should be whitelisted")
	}
	if !risk.IsWhitelisted("192.168.1.1") {
		t.Error("192.168.1.1 should be whitelisted")
	}
	if risk.IsWhitelisted("8.8.8.8") {
		t.Error("8.8.8.8 should not be whitelisted")
	}
}

func TestIPRiskEmptyConfig(t *testing.T) {
	cfg := IPRiskConfig{Enabled: true}
	risk := NewIPRisk(cfg)

	if got := risk.Evaluate("RU"); got != RiskLow {
		t.Errorf("Evaluate with empty config = %v, want RiskLow", got)
	}
}
