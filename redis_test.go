package guard

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/zeromicro/go-zero/core/stores/redis"
)

func testRedis(t testing.TB) *redis.Redis {
	t.Helper()
	mr := newMiniRedis(t)

	rds, err := redis.NewRedis(redis.RedisConf{
		Host: mr.Addr(),
		Type: "node",
	})
	if err != nil {
		t.Fatalf("redis.NewRedis: %v", err)
	}

	return rds
}

func newMiniRedis(t testing.TB) *miniredis.Miniredis {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	t.Cleanup(mr.Close)

	return mr
}

// deadRedis hands back a client whose server has already shut down, so commands
// fail fast on the error path instead of hanging.
func deadRedis(t testing.TB) *redis.Redis {
	t.Helper()
	mr := newMiniRedis(t)

	rds, err := redis.NewRedis(redis.RedisConf{
		Host:        mr.Addr(),
		Type:        "node",
		PingTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("redis.NewRedis: %v", err)
	}

	mr.Close()
	return rds
}
