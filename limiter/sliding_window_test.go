package limiter

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/zeromicro/go-zero/core/stores/redis"
)

func testRedis(t *testing.T) *redis.Redis {
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

func cleanKeys(t *testing.T, rds *redis.Redis) {
	t.Helper()
	_, _ = rds.Eval(
		`local ks = redis.call('KEYS', ARGV[1]) for _,k in ipairs(ks) do redis.call('DEL',k) end return #ks`,
		[]string{},
		[]string{"rate:limit:*"},
	)
}

func TestAllow_guestUnderLimit(t *testing.T) {
	rds := testRedis(t)
	cleanKeys(t, rds)

	cfg := Config{WindowSec: 60, GuestLimit: 3, UserLimit: 10, AdminBypass: true}
	lim := New(rds, cfg)

	for i := 0; i < 3; i++ {
		allowed, err := lim.Allow(RoleGuest, "guest-1")
		if err != nil {
			t.Fatal(err)
		}
		if !allowed {
			t.Errorf("iteration %d: expected allowed", i)
		}
	}
}

func TestAllow_guestExceedsLimit(t *testing.T) {
	rds := testRedis(t)
	cleanKeys(t, rds)

	lim := New(rds, Config{WindowSec: 60, GuestLimit: 3, UserLimit: 10})

	for i := 0; i < 3; i++ {
		lim.Allow(RoleGuest, "guest-2")
	}
	allowed, err := lim.Allow(RoleGuest, "guest-2")
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Error("expected blocked after exceeding limit")
	}
}

func TestAllow_userHigherLimit(t *testing.T) {
	rds := testRedis(t)
	cleanKeys(t, rds)

	lim := New(rds, Config{WindowSec: 60, GuestLimit: 3, UserLimit: 10})

	guestBlocked := 0
	for i := 0; i < 7; i++ {
		if a, _ := lim.Allow(RoleGuest, "compare"); !a {
			guestBlocked++
		}
		if a, _ := lim.Allow(RoleUser, "compare"); !a {
			t.Errorf("user blocked on attempt %d", i+1)
		}
	}
	if guestBlocked == 0 {
		t.Error("expected guest to be blocked")
	}
}

func TestAllow_adminBypass(t *testing.T) {
	rds := testRedis(t)
	cleanKeys(t, rds)

	lim := New(rds, Config{WindowSec: 60, GuestLimit: 3, AdminBypass: true})

	for i := 0; i < 100; i++ {
		allowed, err := lim.Allow(RoleAdmin, "admin-1")
		if err != nil {
			t.Fatal(err)
		}
		if !allowed {
			t.Error("admin should bypass limit")
			break
		}
	}
}

func TestAllow_separateIDs(t *testing.T) {
	rds := testRedis(t)
	cleanKeys(t, rds)

	lim := New(rds, Config{WindowSec: 60, GuestLimit: 3, UserLimit: 10})

	for i := 0; i < 3; i++ {
		lim.Allow(RoleGuest, "a")
	}
	allowed, err := lim.Allow(RoleGuest, "b")
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Error("separate ID should have own counter")
	}
}

func TestCount(t *testing.T) {
	rds := testRedis(t)
	cleanKeys(t, rds)

	lim := New(rds, Config{WindowSec: 60, GuestLimit: 10, UserLimit: 10})

	lim.Allow(RoleGuest, "count")
	lim.Allow(RoleGuest, "count")

	c, err := lim.Count(RoleGuest, "count")
	if err != nil {
		t.Fatal(err)
	}
	if c != 2 {
		t.Errorf("Count = %d, want 2", c)
	}
}
