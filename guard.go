package guard

import (
	"github.com/Vierblatt/rate-limit-guard/iprisk"
	"github.com/Vierblatt/rate-limit-guard/limiter"
	"github.com/zeromicro/go-zero/core/stores/redis"
)

type Guard struct {
	config    Config
	redis     *redis.Redis
	limiter   *limiter.SlidingWindowLimiter
	ipRisk    *iprisk.IPRisk
	blacklist *iprisk.Blacklist
	metrics   *Metrics
}

func NewGuard(cfg Config) *Guard {
	applyDefaults(&cfg)

	rds := redis.MustNewRedis(redis.RedisConf{
		Host: cfg.RedisAddr,
		Pass: cfg.RedisPass,
		Type: "node",
	})

	return newGuardWithRedis(cfg, rds)
}

func NewGuardWithRedis(cfg Config, rds *redis.Redis) *Guard {
	applyDefaults(&cfg)
	return newGuardWithRedis(cfg, rds)
}

func newGuardWithRedis(cfg Config, rds *redis.Redis) *Guard {
	return &Guard{
		config:    cfg,
		redis:     rds,
		limiter:   limiter.New(rds, cfg.Limiter),
		ipRisk:    iprisk.New(cfg.IPRisk),
		blacklist: iprisk.NewBlacklist(rds, cfg.IPRisk),
		metrics:   NewMetrics(),
	}
}

func (g *Guard) Redis() *redis.Redis {
	return g.redis
}

func (g *Guard) Metrics() *Metrics {
	return g.metrics
}

func (g *Guard) Config() Config {
	return g.config
}

func applyDefaults(cfg *Config) {
	if len(cfg.Privacy.SensitiveHeaders) == 0 {
		cfg.Privacy.SensitiveHeaders = []string{"Authorization", "Email", "Device-Id", "X-Device-Id"}
	}
	if len(cfg.IPRisk.HighRiskCountries) == 0 {
		cfg.IPRisk.HighRiskCountries = []string{"RU", "UA", "NG", "BD", "PK", "VN", "ID"}
	}
	if cfg.IPRisk.BlacklistTTL <= 0 {
		cfg.IPRisk.BlacklistTTL = 10
	}
	if cfg.IPRisk.MaxFails <= 0 {
		cfg.IPRisk.MaxFails = 3
	}
}
