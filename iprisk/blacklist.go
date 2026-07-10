package iprisk

import (
	"fmt"
	"time"

	"github.com/zeromicro/go-zero/core/stores/redis"
)

type Blacklist struct {
	redis  *redis.Redis
	config Config
}

func NewBlacklist(rds *redis.Redis, cfg Config) *Blacklist {
	return &Blacklist{redis: rds, config: cfg}
}

func (b *Blacklist) key(ip string) string {
	return fmt.Sprintf("rate:blacklist:%s", ip)
}

func (b *Blacklist) failKey(ip string) string {
	return fmt.Sprintf("rate:fails:%s", ip)
}

func (b *Blacklist) IsBlocked(ip string) (bool, error) {
	val, err := b.redis.Exists(b.key(ip))
	if err != nil {
		return false, err
	}
	return val, nil
}

func (b *Blacklist) RecordFail(ip string) (bool, error) {
	key := b.failKey(ip)
	ttl := int(b.config.BlacklistTTL * 60)

	count, err := b.redis.Incr(key)
	if err != nil {
		return false, err
	}

	if count == 1 {
		if err := b.redis.Expire(key, ttl); err != nil {
			return false, err
		}
	}

	if int(count) >= b.config.MaxFails {
		if err := b.redis.Setex(b.key(ip), "1", ttl); err != nil {
			return false, err
		}
		if _, err := b.redis.Del(key); err != nil {
			return false, err
		}
		return true, nil
	}

	return false, nil
}

func (b *Blacklist) Remove(ip string) error {
	_, err := b.redis.Del(b.key(ip), b.failKey(ip))
	return err
}

func (b *Blacklist) Block(ip string, duration time.Duration) error {
	return b.redis.Setex(b.key(ip), "1", int(duration.Seconds()))
}
