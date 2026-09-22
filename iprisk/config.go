package iprisk

type Config struct {
	Enabled      bool `json:",default=true"`
	BlacklistTTL int  `json:",default=10"`
	MaxFails     int  `json:",default=3"`
	// RiskQuotaRatio scales the rate limit quota for requests from high-risk
	// regions. 0.2 means a high-risk caller gets 20% of the normal quota.
	RiskQuotaRatio    float64  `json:",default=0.2"`
	CountryHeader     string   `json:",default=CF-IPCountry"`
	Whitelist         []string `json:",optional"`
	HighRiskCountries []string `json:",optional"`
}
