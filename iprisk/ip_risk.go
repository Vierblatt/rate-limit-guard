package iprisk

type RiskLevel int

const (
	RiskLow RiskLevel = iota
	RiskMid
	RiskHigh
)

func (r RiskLevel) String() string {
	switch r {
	case RiskLow:
		return "low"
	case RiskMid:
		return "mid"
	case RiskHigh:
		return "high"
	default:
		return "unknown"
	}
}

type IPRisk struct {
	config    Config
	riskCache map[string]RiskLevel
}

func New(cfg Config) *IPRisk {
	rc := make(map[string]RiskLevel, len(cfg.HighRiskCountries))
	for _, code := range cfg.HighRiskCountries {
		rc[code] = RiskHigh
	}

	return &IPRisk{
		config:    cfg,
		riskCache: rc,
	}
}

func (r *IPRisk) Evaluate(countryCode string) RiskLevel {
	if !r.config.Enabled {
		return RiskLow
	}

	if level, ok := r.riskCache[countryCode]; ok {
		return level
	}

	return RiskLow
}

func (r *IPRisk) IsWhitelisted(ip string) bool {
	for _, wl := range r.config.Whitelist {
		if wl == ip {
			return true
		}
	}
	return false
}
