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
