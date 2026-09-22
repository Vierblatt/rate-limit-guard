package limiter

import "testing"

func TestLimitFor(t *testing.T) {
	cfg := Config{WindowSec: 60, GuestLimit: 30, UserLimit: 100, AdminBypass: true}
	lim := New(nil, cfg)

	tests := []struct {
		name string
		role Role
		want int
	}{
		{"guest", RoleGuest, 30},
		{"user", RoleUser, 100},
		{"admin bypass is exempt", RoleAdmin, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := lim.LimitFor(tt.role); got != tt.want {
				t.Errorf("LimitFor(%v) = %d, want %d", tt.role, got, tt.want)
			}
		})
	}

	t.Run("non-bypassing admin shares user tier", func(t *testing.T) {
		noBypass := New(nil, Config{GuestLimit: 30, UserLimit: 100, AdminBypass: false})
		if got := noBypass.LimitFor(RoleAdmin); got != 100 {
			t.Errorf("LimitFor(admin) = %d, want 100", got)
		}
	})

	t.Run("unknown role is exempt", func(t *testing.T) {
		if got := lim.LimitFor(Role(99)); got != 0 {
			t.Errorf("LimitFor(unknown) = %d, want 0", got)
		}
	})
}

func TestAllowN_nonPositiveLimitAllows(t *testing.T) {
	rds := testRedis(t)
	lim := New(rds, Config{WindowSec: 60, GuestLimit: 1, UserLimit: 1})

	for _, limit := range []int{0, -1} {
		for i := 0; i < 10; i++ {
			allowed, err := lim.AllowN(RoleGuest, "exempt", limit)
			if err != nil {
				t.Fatal(err)
			}
			if !allowed {
				t.Fatalf("limit %d: attempt %d should be allowed", limit, i+1)
			}
		}
	}
}

func TestAllowN_explicitQuota(t *testing.T) {
	rds := testRedis(t)
	cleanKeys(t, rds)

	// The configured guest quota is 100, but the caller tightens it to 2.
	lim := New(rds, Config{WindowSec: 60, GuestLimit: 100, UserLimit: 100})

	for i := 0; i < 2; i++ {
		allowed, err := lim.AllowN(RoleGuest, "tightened", 2)
		if err != nil {
			t.Fatal(err)
		}
		if !allowed {
			t.Fatalf("attempt %d should be allowed under quota 2", i+1)
		}
	}

	allowed, err := lim.AllowN(RoleGuest, "tightened", 2)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Error("third attempt should be rejected by the explicit quota")
	}
}

func TestRoleString(t *testing.T) {
	tests := map[Role]string{
		RoleGuest: "guest",
		RoleUser:  "user",
		RoleAdmin: "admin",
		Role(99):  "unknown",
	}
	for role, want := range tests {
		if got := role.String(); got != want {
			t.Errorf("Role(%d).String() = %q, want %q", int(role), got, want)
		}
	}
}

func TestAllow_redisError(t *testing.T) {
	rds := deadRedis(t)

	lim := New(rds, Config{WindowSec: 60, GuestLimit: 10, UserLimit: 10})
	if _, err := lim.Allow(RoleGuest, "boom"); err == nil {
		t.Error("expected an error when Redis is unreachable")
	}
}

func TestCount_redisError(t *testing.T) {
	rds := deadRedis(t)

	lim := New(rds, Config{WindowSec: 60, GuestLimit: 10, UserLimit: 10})
	if _, err := lim.Count(RoleGuest, "boom"); err == nil {
		t.Error("expected an error when Redis is unreachable")
	}
}

func TestNew_keepsConfig(t *testing.T) {
	cfg := Config{WindowSec: 30, GuestLimit: 7, UserLimit: 42, AdminBypass: false}
	lim := New(nil, cfg)

	if lim.config != cfg {
		t.Errorf("New() config = %+v, want %+v", lim.config, cfg)
	}
}
