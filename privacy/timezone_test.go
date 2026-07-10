package privacy

import (
	"net/http"
	"testing"
)

func TestParseTimezone(t *testing.T) {
	p := NewTimezoneParser("X-Timezone")

	tests := []struct {
		header string
		value  string
		want   string
	}{
		{"X-Timezone", "America/New_York", "America/New_York"},
		{"X-Timezone", "Asia/Shanghai", "Asia/Shanghai"},
		{"X-Timezone", "", "UTC"},
		{"X-Timezone", "Invalid/Zone", "UTC"},
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

func TestParseTimezone_customHeader(t *testing.T) {
	p := NewTimezoneParser("X-Client-Timezone")

	h := http.Header{}
	h.Set("X-Client-Timezone", "Europe/London")

	loc := p.Parse(h)
	if loc.String() != "Europe/London" {
		t.Errorf("Parse = %s, want Europe/London", loc)
	}
}
