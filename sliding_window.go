package guard

import (
	"fmt"
	"math/rand"
	"strconv"
	"time"

	"github.com/zeromicro/go-zero/core/stores/redis"
)

type Role int

const (
	RoleGuest Role = iota
	RoleUser
	RoleAdmin
)

func (r Role) String() string {
	switch r {
	case RoleGuest:
		return "guest"
	case RoleUser:
		return "user"
	case RoleAdmin:
		return "admin"
	default:
		return "unknown"
	}
}

type SlidingWindowLimiter struct {
	redis  *redis.Redis
	config LimiterConfig
}

func NewSlidingWindowLimiter(rds *redis.Redis, cfg LimiterConfig) *SlidingWindowLimiter {
	return &SlidingWindowLimiter{redis: rds, config: cfg}
}

func (l *SlidingWindowLimiter) Allow(role Role, id string) (bool, error) {
	if role == RoleAdmin && l.config.AdminBypass {
		return true, nil
	}

	key := fmt.Sprintf("rate:limit:%s:%s", role, id)
	now := time.Now().UnixMilli()
	window := int64(l.config.WindowSec) * 1000
	member := fmt.Sprintf("%d:%d", now, rand.Int63())

	var limit int
	switch role {
	case RoleGuest:
		limit = l.config.GuestLimit
	case RoleUser:
		limit = l.config.UserLimit
	default:
		return true, nil
	}

	script := `
local key = KEYS[1]
local window = tonumber(ARGV[1])
local now = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local count = redis.call('ZCARD', key)
if count < limit then
    redis.call('ZADD', key, now, member)
    redis.call('EXPIRE', key, math.ceil(window / 1000) + 1)
    return 1
end
return 0
`
	val, err := l.redis.Eval(script, []string{key}, []string{
		strconv.FormatInt(window, 10),
		strconv.FormatInt(now, 10),
		strconv.Itoa(limit),
		member,
	})
	if err != nil {
		return false, err
	}

	result, ok := val.(int64)
	if !ok {
		return false, fmt.Errorf("unexpected redis reply type: %T", val)
	}

	return result == 1, nil
}

func (l *SlidingWindowLimiter) Count(role Role, id string) (int, error) {
	key := fmt.Sprintf("rate:limit:%s:%s", role, id)
	return l.redis.Zcard(key)
}
