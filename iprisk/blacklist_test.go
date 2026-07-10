package iprisk

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/zeromicro/go-zero/core/stores/redis"
)

func blTestRedis(t *testing.T) *redis.Redis {
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

func cleanBlacklist(t *testing.T, rds *redis.Redis) {
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

func TestBlacklist_blockAndCheck(t *testing.T) {
	rds := blTestRedis(t)
	cleanBlacklist(t, rds)

	bl := NewBlacklist(rds, Config{BlacklistTTL: 1, MaxFails: 3})

	blocked, err := bl.IsBlocked("10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if blocked {
		t.Error("should not be blocked initially")
	}
}

func TestBlacklist_recordFail(t *testing.T) {
	rds := blTestRedis(t)
	cleanBlacklist(t, rds)

	bl := NewBlacklist(rds, Config{BlacklistTTL: 1, MaxFails: 3})

	for i := 0; i < 2; i++ {
		b, err := bl.RecordFail("10.0.0.2")
		if err != nil {
			t.Fatal(err)
		}
		if b {
			t.Error("should not block before max fails")
		}
	}

	b, err := bl.RecordFail("10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if !b {
		t.Fatal("should be blocked after 3 failures")
	}

	blocked, _ := bl.IsBlocked("10.0.0.2")
	if !blocked {
		t.Error("should be in blacklist")
	}
}

func TestBlacklist_remove(t *testing.T) {
	rds := blTestRedis(t)
	cleanBlacklist(t, rds)

	bl := NewBlacklist(rds, Config{BlacklistTTL: 10, MaxFails: 1})
	bl.RecordFail("10.0.0.3")

	if err := bl.Remove("10.0.0.3"); err != nil {
		t.Fatal(err)
	}
	blocked, _ := bl.IsBlocked("10.0.0.3")
	if blocked {
		t.Error("should not be blocked after remove")
	}
}

func TestBlacklist_block(t *testing.T) {
	rds := blTestRedis(t)
	cleanBlacklist(t, rds)

	bl := NewBlacklist(rds, Config{})
	if err := bl.Block("10.0.0.4", time.Minute); err != nil {
		t.Fatal(err)
	}

	blocked, _ := bl.IsBlocked("10.0.0.4")
	if !blocked {
		t.Error("should be blocked after explicit Block")
	}
}
