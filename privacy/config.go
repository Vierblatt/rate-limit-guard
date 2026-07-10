package privacy

type Config struct {
	Enabled          bool     `json:",default=true"`
	SensitiveHeaders []string `json:",optional"`
	TimezoneHeader   string   `json:",default=X-Timezone"`
}
