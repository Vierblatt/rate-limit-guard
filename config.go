package guard

type Config struct {
	Limiter LimiterConfig
	IPRisk  IPRiskConfig
	Privacy PrivacyConfig
}

type LimiterConfig struct {
	RedisAddr   string `json:",default=localhost:6379"`
	RedisPass   string `json:",optional"`
	RedisDB     int    `json:",default=0"`
	WindowSec   int    `json:",default=60"`
	GuestLimit  int    `json:",default=30"`
	UserLimit   int    `json:",default=100"`
	AdminBypass bool   `json:",default=true"`
}

type IPRiskConfig struct {
	Enabled           bool     `json:",default=true"`
	BlacklistTTL      int      `json:",default=10"`
	MaxFails          int      `json:",default=3"`
	Whitelist         []string `json:",optional"`
	HighRiskCountries []string `json:",optional"`
}

type PrivacyConfig struct {
	Enabled          bool     `json:",default=true"`
	SensitiveHeaders []string `json:",optional"`
	TimezoneHeader   string   `json:",default=X-Timezone"`
}
