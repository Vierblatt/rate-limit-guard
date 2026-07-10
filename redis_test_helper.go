package guard

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/zeromicro/go-zero/core/stores/redis"
)

func testRedis(t testing.TB) *redis.Redis {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	t.Cleanup(mr.Close)

	rds, err := redis.NewRedis(redis.RedisConf{
		Host: mr.Addr(),
		Type: "node",
	})
	if err != nil {
		t.Fatalf("redis.NewRedis: %v", err)
	}

	return rds
}

func cleanRateLimitKeys(t *testing.T, rds *redis.Redis) {
	t.Helper()
	_, _ = rds.Eval(
		`local ks = redis.call('KEYS', ARGV[1]) for _,k in ipairs(ks) do redis.call('DEL',k) end return #ks`,
		[]string{},
		[]string{"rate:limit:*"},
	)
}

func cleanBlacklistKeys(t *testing.T, rds *redis.Redis) {
	t.Helper()
	_, _ = rds.Eval(
		`local ks = redis.call('KEYS', ARGV[1]) for _,k in ipairs(ks) do redis.call('DEL',k) end return #ks`,
		[]string{},
		[]string{"rate:blacklist:*"},
	)
	_, _ = rds.Eval(
		`local ks = redis.call('KEYS', ARGV[1]) for _,k in ipairs(ks) do redis.call('DEL',k) end return #ks`,
		[]string{},
		[]string{"rate:fails:*"},
	)
}
