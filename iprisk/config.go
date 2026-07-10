package iprisk

type Config struct {
	Enabled           bool     `json:",default=true"`
	BlacklistTTL      int      `json:",default=10"`
	MaxFails          int      `json:",default=3"`
	Whitelist         []string `json:",optional"`
	HighRiskCountries []string `json:",optional"`
}
