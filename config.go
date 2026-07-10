package guard

import (
	"github.com/Vierblatt/rate-limit-guard/iprisk"
	"github.com/Vierblatt/rate-limit-guard/limiter"
	"github.com/Vierblatt/rate-limit-guard/privacy"
	"github.com/zeromicro/go-zero/core/conf"
)

type Config struct {
	RedisAddr string          `json:",default=localhost:6379"`
	RedisPass string          `json:",optional"`
	RedisDB   int             `json:",default=0"`
	Limiter   limiter.Config  `json:",optional"`
	IPRisk    iprisk.Config   `json:",optional"`
	Privacy   privacy.Config  `json:",optional"`
}

func MustLoadConfig(path string) *Config {
	var cfg Config
	conf.MustLoad(path, &cfg)
	return &cfg
}
