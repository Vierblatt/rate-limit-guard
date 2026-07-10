package limiter

type Config struct {
	WindowSec   int  `json:",default=60"`
	GuestLimit  int  `json:",default=30"`
	UserLimit   int  `json:",default=100"`
	AdminBypass bool `json:",default=true"`
}
