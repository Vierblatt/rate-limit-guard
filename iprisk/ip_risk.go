package iprisk

import (
	"net/http"
	"strings"
)

type RiskLevel int

const (
	RiskLow RiskLevel = iota
	RiskMid
	RiskHigh
)

// unknownCountry is what CDNs (e.g. Cloudflare) send when the client IP cannot
// be geolocated. It must never be treated as a high-risk region.
const unknownCountry = "XX"

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

	code := strings.ToUpper(strings.TrimSpace(countryCode))
	if code == "" || code == unknownCountry {
		return RiskLow
	}

	if level, ok := r.riskCache[code]; ok {
		return level
	}

	return RiskLow
}

// CountryFrom reads the client country code from the configured trusted header.
// It must only be enabled when a trusted edge (CDN / gateway) sets that header;
// otherwise clients could spoof their region.
func (r *IPRisk) CountryFrom(h http.Header) string {
	if !r.config.Enabled || r.config.CountryHeader == "" {
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(h.Get(r.config.CountryHeader)))
}

// Quota scales base by the risk level of countryCode. High-risk regions get
// RiskQuotaRatio of the normal quota; everything else is unchanged. A
// non-positive base (exempt role) is returned as-is.
func (r *IPRisk) Quota(countryCode string, base int) int {
	if base <= 0 {
		return base
	}
	if r.Evaluate(countryCode) != RiskHigh {
		return base
	}

	ratio := r.config.RiskQuotaRatio
	if ratio <= 0 || ratio > 1 {
		ratio = 1
	}

	quota := int(float64(base) * ratio)
	if quota < 1 {
		quota = 1
	}
	return quota
}

func (r *IPRisk) IsWhitelisted(ip string) bool {
	for _, wl := range r.config.Whitelist {
		if wl == ip {
			return true
		}
	}
	return false
}
