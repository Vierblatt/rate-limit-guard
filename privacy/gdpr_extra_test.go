package privacy

import (
	"net/http"
	"strings"
	"testing"
)

func TestSanitizeHeader_categories(t *testing.T) {
	s := NewSanitizer(Config{})

	tests := []struct {
		name      string
		key       string
		value     string
		wantExact string
		// wantRedacted asserts the secret does not survive verbatim, which is
		// the property that actually matters for GDPR compliance.
		wantRedacted bool
	}{
		{
			name: "authorization uses the bearer mask",
			key:  "Authorization", value: "Bearer abcdef123456",
			wantExact: "Bearer abcd****", wantRedacted: true,
		},
		{
			name: "email keeps the domain",
			key:  "Email", value: "alice@example.com",
			wantExact: "a****e@example.com", wantRedacted: true,
		},
		{
			name: "x-email is treated as an email",
			key:  "X-Email", value: "bob@example.com",
			wantExact: "b****b@example.com", wantRedacted: true,
		},
		{
			name: "device-id uses the device mask",
			key:  "Device-Id", value: "abc12345xyz",
			wantExact: "ab****yz", wantRedacted: true,
		},
		{
			name: "x-device-id uses the device mask",
			key:  "X-Device-Id", value: "abc12345xyz",
			wantExact: "ab****yz", wantRedacted: true,
		},
		{
			name: "unknown keys fall back to the generic mask",
			key:  "X-Custom-Secret", value: "sensitivevalue",
			wantExact: "se****ue", wantRedacted: true,
		},
		{
			name: "case-insensitive matching",
			key:  "AUTHORIZATION", value: "Bearer abcdef123456",
			wantExact: "Bearer abcd****", wantRedacted: true,
		},
		{
			name: "empty value stays empty",
			key:  "Authorization", value: "",
			wantExact: "", wantRedacted: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			if tt.value != "" {
				h.Set(tt.key, tt.value)
			}

			got := s.SanitizeHeader(h, tt.key)
			if got != tt.wantExact {
				t.Errorf("SanitizeHeader(%q, %q) = %q, want %q", tt.key, tt.value, got, tt.wantExact)
			}
			if tt.wantRedacted && tt.value != "" && strings.Contains(got, tt.value) {
				t.Errorf("value %q leaked through the mask as %q", tt.value, got)
			}
		})
	}
}

func TestMaskGeneric(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"sensitivevalue", "se****ue"},
		{"abcde", "ab****de"},
		{"abcd", "****"},
		{"abc", "****"},
		{"", "****"},
	}

	for _, tt := range tests {
		if got := maskGeneric(tt.input); got != tt.want {
			t.Errorf("maskGeneric(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizeHeader_missingKeyReturnsEmpty(t *testing.T) {
	s := NewSanitizer(Config{})

	if got := s.SanitizeHeader(http.Header{}, "Authorization"); got != "" {
		t.Errorf("SanitizeHeader on a missing key = %q, want empty", got)
	}
}

func TestSanitizeHeaders_emptySensitiveListIsNoop(t *testing.T) {
	s := NewSanitizer(Config{Enabled: true})

	h := http.Header{}
	h.Set("Authorization", "Bearer secret123")

	sanitized := s.SanitizeHeaders(h)
	if sanitized.Get("Authorization") != "Bearer secret123" {
		t.Error("nothing should be masked when the sensitive list is empty")
	}
}
