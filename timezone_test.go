package guard

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestParseTimezone(t *testing.T) {
	p := newTimezoneParser("X-Timezone")

	tests := []struct {
		header string
		value  string
		want   string
	}{
		{"X-Timezone", "America/New_York", "America/New_York"},
		{"X-Timezone", "Asia/Shanghai", "Asia/Shanghai"},
		{"X-Timezone", "", "UTC"},
		{"X-Timezone", "Invalid/Zone", "UTC"},
		{"", "", "UTC"},
	}

	for _, tt := range tests {
		h := http.Header{}
		if tt.value != "" {
			h.Set(tt.header, tt.value)
		}
		loc := p.Parse(h)
		if loc.String() != tt.want {
			t.Errorf("Parse(%q) = %s, want %s", tt.value, loc, tt.want)
		}
	}
}

func TestTimezoneCustomHeader(t *testing.T) {
	p := newTimezoneParser("X-Client-Timezone")

	h := http.Header{}
	h.Set("X-Client-Timezone", "Europe/London")

	loc := p.Parse(h)
	if loc.String() != "Europe/London" {
		t.Errorf("Parse() = %s, want Europe/London", loc)
	}
}

func TestContextTimezone(t *testing.T) {
	loc, _ := time.LoadLocation("Asia/Tokyo")
	ctx := WithTimezone(context.Background(), loc)
	result := GetTimezone(ctx)
	if result.String() != "Asia/Tokyo" {
		t.Errorf("GetTimezone() = %s, want Asia/Tokyo", result)
	}

	ctx = WithTimezone(context.Background(), nil)
	result = GetTimezone(ctx)
	if result.String() != "UTC" {
		t.Errorf("GetTimezone() with nil = %s, want UTC", result)
	}
}
