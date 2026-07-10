package guard

import (
	"github.com/zeromicro/go-zero/core/conf"
	"github.com/zeromicro/go-zero/core/stores/redis"
)

type Guard struct {
	config    Config
	redis     *redis.Redis
	limiter   *SlidingWindowLimiter
	ipRisk    *IPRisk
	blacklist *Blacklist
	metrics   *Metrics
}

func NewGuard(cfg Config) *Guard {
	applyDefaults(&cfg)

	rds := redis.MustNewRedis(redis.RedisConf{
		Host: cfg.Limiter.RedisAddr,
		Pass: cfg.Limiter.RedisPass,
		Type: "node",
	})

	return newGuardWithRedis(cfg, rds)
}

func NewGuardWithRedis(cfg Config, rds *redis.Redis) *Guard {
	applyDefaults(&cfg)
	return newGuardWithRedis(cfg, rds)
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

func newGuardWithRedis(cfg Config, rds *redis.Redis) *Guard {
	return &Guard{
		config:    cfg,
		redis:     rds,
		limiter:   NewSlidingWindowLimiter(rds, cfg.Limiter),
		ipRisk:    NewIPRisk(cfg.IPRisk),
		blacklist: NewBlacklist(rds, cfg.IPRisk),
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

func MustLoadConfig(path string) *Config {
	var cfg Config
	conf.MustLoad(path, &cfg)
	return &cfg
}
