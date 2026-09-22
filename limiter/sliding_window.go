package limiter

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
	config Config
}

func New(rds *redis.Redis, cfg Config) *SlidingWindowLimiter {
	return &SlidingWindowLimiter{redis: rds, config: cfg}
}

// LimitFor returns the per-window quota for role. A non-positive result means
// the role is exempt from limiting.
func (l *SlidingWindowLimiter) LimitFor(role Role) int {
	switch role {
	case RoleGuest:
		return l.config.GuestLimit
	case RoleUser:
		return l.config.UserLimit
	case RoleAdmin:
		if l.config.AdminBypass {
			return 0
		}
		// No dedicated admin quota: a non-bypassing admin shares the user tier.
		return l.config.UserLimit
	default:
		return 0
	}
}

func (l *SlidingWindowLimiter) Allow(role Role, id string) (bool, error) {
	return l.AllowN(role, id, l.LimitFor(role))
}

// AllowN applies an explicit quota, letting callers (e.g. IP risk control)
// tighten the limit for a single request. A non-positive limit allows the call.
func (l *SlidingWindowLimiter) AllowN(role Role, id string, limit int) (bool, error) {
	if limit <= 0 {
		return true, nil
	}

	key := fmt.Sprintf("rate:limit:%s:%s", role, id)
	now := time.Now().UnixMilli()
	window := int64(l.config.WindowSec) * 1000
	member := fmt.Sprintf("%d:%d", now, rand.Int63())

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
