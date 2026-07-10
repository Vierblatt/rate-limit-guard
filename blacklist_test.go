package guard

import (
	"testing"
	"time"
)

func TestBlacklist_BlockAndCheck(t *testing.T) {
	rds := testRedis(t)
	cleanBlacklistKeys(t, rds)

	cfg := IPRiskConfig{BlacklistTTL: 1, MaxFails: 3}
	bl := NewBlacklist(rds, cfg)

	blocked, err := bl.IsBlocked("10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if blocked {
		t.Error("should not be blocked initially")
	}
}

func TestBlacklist_RecordFail(t *testing.T) {
	rds := testRedis(t)
	cleanBlacklistKeys(t, rds)

	cfg := IPRiskConfig{BlacklistTTL: 1, MaxFails: 3}
	bl := NewBlacklist(rds, cfg)

	for i := 0; i < 2; i++ {
		blocked, err := bl.RecordFail("10.0.0.2")
		if err != nil {
			t.Fatal(err)
		}
		if blocked {
			t.Error("should not block before max fails")
		}
	}

	blocked, err := bl.RecordFail("10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if !blocked {
		t.Error("should be blocked after 3 failures")
	}

	blocked, err = bl.IsBlocked("10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if !blocked {
		t.Error("should be in blacklist after max fails")
	}
}

func TestBlacklist_Remove(t *testing.T) {
	rds := testRedis(t)
	cleanBlacklistKeys(t, rds)

	cfg := IPRiskConfig{BlacklistTTL: 10, MaxFails: 1}
	bl := NewBlacklist(rds, cfg)

	bl.RecordFail("10.0.0.3")

	if err := bl.Remove("10.0.0.3"); err != nil {
		t.Fatal(err)
	}

	blocked, err := bl.IsBlocked("10.0.0.3")
	if err != nil {
		t.Fatal(err)
	}
	if blocked {
		t.Error("should not be blocked after remove")
	}
}

func TestBlacklist_Block(t *testing.T) {
	rds := testRedis(t)
	cleanBlacklistKeys(t, rds)

	cfg := IPRiskConfig{}
	bl := NewBlacklist(rds, cfg)

	if err := bl.Block("10.0.0.4", time.Minute); err != nil {
		t.Fatal(err)
	}

	blocked, err := bl.IsBlocked("10.0.0.4")
	if err != nil {
		t.Fatal(err)
	}
	if !blocked {
		t.Error("should be blocked after explicit Block")
	}
}
