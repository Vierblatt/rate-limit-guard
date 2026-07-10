package guard

import (
	"testing"
)

func TestSlidingWindowLimiter_Allow(t *testing.T) {
	rds := testRedis(t)
	cleanRateLimitKeys(t, rds)

	cfg := LimiterConfig{
		WindowSec:   60,
		GuestLimit:  3,
		UserLimit:   10,
		AdminBypass: true,
	}
	lim := NewSlidingWindowLimiter(rds, cfg)

	t.Run("guest under limit", func(t *testing.T) {
		cleanRateLimitKeys(t, rds)
		for i := 0; i < 3; i++ {
			allowed, err := lim.Allow(RoleGuest, "test-guest-1")
			if err != nil {
				t.Fatal(err)
			}
			if !allowed {
				t.Errorf("iteration %d: expected allowed, got blocked", i)
			}
		}
	})

	t.Run("guest exceeds limit", func(t *testing.T) {
		cleanRateLimitKeys(t, rds)
		for i := 0; i < 3; i++ {
			lim.Allow(RoleGuest, "test-guest-2")
		}
		allowed, err := lim.Allow(RoleGuest, "test-guest-2")
		if err != nil {
			t.Fatal(err)
		}
		if allowed {
			t.Error("expected blocked after exceeding limit")
		}
	})

	t.Run("user has higher limit", func(t *testing.T) {
		cleanRateLimitKeys(t, rds)
		guestBlocked := 0
		userBlocked := 0
		for i := 0; i < 7; i++ {
			if a, _ := lim.Allow(RoleGuest, "test-user-compare"); !a {
				guestBlocked++
			}
			if a, _ := lim.Allow(RoleUser, "test-user-compare"); !a {
				userBlocked++
			}
		}
		if guestBlocked == 0 {
			t.Error("expected guest to be blocked at limit 3")
		}
		if userBlocked > 0 {
			t.Errorf("expected user not to be blocked at limit 10, blocked %d times", userBlocked)
		}
	})

	t.Run("admin bypass", func(t *testing.T) {
		cleanRateLimitKeys(t, rds)
		for i := 0; i < 100; i++ {
			allowed, err := lim.Allow(RoleAdmin, "test-admin")
			if err != nil {
				t.Fatal(err)
			}
			if !allowed {
				t.Error("admin should always be allowed")
				break
			}
		}
	})

	t.Run("separate IDs have separate counters", func(t *testing.T) {
		cleanRateLimitKeys(t, rds)
		for i := 0; i < 3; i++ {
			lim.Allow(RoleGuest, "counter-a")
		}
		allowed, err := lim.Allow(RoleGuest, "counter-b")
		if err != nil {
			t.Fatal(err)
		}
		if !allowed {
			t.Error("counter-b should have own limit, not affected by counter-a")
		}
	})
}

func TestSlidingWindowLimiter_Count(t *testing.T) {
	rds := testRedis(t)
	cleanRateLimitKeys(t, rds)

	cfg := LimiterConfig{WindowSec: 60, GuestLimit: 10, UserLimit: 10}
	lim := NewSlidingWindowLimiter(rds, cfg)

	lim.Allow(RoleGuest, "count-test")
	lim.Allow(RoleGuest, "count-test")

	c, err := lim.Count(RoleGuest, "count-test")
	if err != nil {
		t.Fatal(err)
	}
	if c != 2 {
		t.Errorf("Count = %d, want 2", c)
	}
}
