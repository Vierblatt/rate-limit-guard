package guard

import (
	"net/http"
	"testing"
)

func TestMaskBearer(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Bearer abcdef123456", "Bearer abcd****"},
		{"longertoken1234", "long****"},
		{"abcd", "abcd****"},
		{"abc", "****"},
		{"", "****"},
	}

	for _, tt := range tests {
		got := maskBearer(tt.input)
		if got != tt.want {
			t.Errorf("maskBearer(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestMaskEmail(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"user@example.com", "u****r@example.com"},
		{"ab@test.com", "a****b@test.com"},
		{"a@test.com", "a****@test.com"},
		{"@test.com", "****@test.com"},
		{"noatsign", "no****gn"},
	}

	for _, tt := range tests {
		got := maskEmail(tt.input)
		if got != tt.want {
			t.Errorf("maskEmail(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestMaskDeviceID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"abc12345xyz", "ab****yz"},
		{"abc", "****"},
		{"abcd", "****"},
		{"", "****"},
	}

	for _, tt := range tests {
		got := maskDeviceID(tt.input)
		if got != tt.want {
			t.Errorf("maskDeviceID(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizeHeaders(t *testing.T) {
	cfg := PrivacyConfig{
		Enabled:          true,
		SensitiveHeaders: []string{"Authorization", "Email"},
	}
	s := newSanitizer(cfg)

	h := http.Header{}
	h.Set("Authorization", "Bearer secret123")
	h.Set("Email", "alice@example.com")
	h.Set("X-Request-Id", "abc")

	sanitized := s.SanitizeHeaders(h)

	if sanitized.Get("Authorization") == "Bearer secret123" {
		t.Error("Authorization header was not sanitized")
	}
	if sanitized.Get("Email") == "alice@example.com" {
		t.Error("Email header was not sanitized")
	}
	if sanitized.Get("X-Request-Id") != "abc" {
		t.Error("Non-sensitive header was modified")
	}
}

func TestSanitizeHeaderPreservesOriginal(t *testing.T) {
	cfg := PrivacyConfig{
		Enabled:          true,
		SensitiveHeaders: []string{"Authorization"},
	}
	s := newSanitizer(cfg)

	h := http.Header{}
	h.Set("Authorization", "Bearer secret123")
	h.Set("Email", "alice@example.com")

	s.SanitizeHeaders(h)

	if h.Get("Authorization") != "Bearer secret123" {
		t.Error("Original header was modified by sanitize")
	}
}
