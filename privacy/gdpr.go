package privacy

import (
	"net/http"
	"strings"
)

type Sanitizer struct {
	config Config
}

func NewSanitizer(cfg Config) *Sanitizer {
	return &Sanitizer{config: cfg}
}

func (s *Sanitizer) SanitizeHeader(h http.Header, key string) string {
	val := h.Get(key)
	if val == "" {
		return ""
	}

	switch strings.ToLower(key) {
	case "authorization":
		return maskBearer(val)
	case "email", "x-email":
		return maskEmail(val)
	case "device-id", "x-device-id":
		return maskDeviceID(val)
	default:
		return maskGeneric(val)
	}
}

func (s *Sanitizer) SanitizeHeaders(h http.Header) http.Header {
	sanitized := h.Clone()
	for _, key := range s.config.SensitiveHeaders {
		val := s.SanitizeHeader(h, key)
		if val != "" {
			sanitized.Set(key, val)
		}
	}
	return sanitized
}

func maskBearer(val string) string {
	const prefix = "Bearer "
	if strings.HasPrefix(val, prefix) && len(val) > 12 {
		return prefix + val[len(prefix):len(prefix)+4] + "****"
	}
	if len(val) >= 4 {
		return val[:4] + "****"
	}
	return "****"
}

func maskEmail(val string) string {
	at := strings.IndexByte(val, '@')
	if at < 0 {
		return maskGeneric(val)
	}
	domain := val[at:]
	if at == 0 {
		return "****" + domain
	}
	local := val[:at]
	if len(local) == 1 {
		return local + "****" + domain
	}
	return local[:1] + "****" + local[len(local)-1:] + domain
}

func maskDeviceID(val string) string {
	if len(val) <= 4 {
		return "****"
	}
	return val[:2] + "****" + val[len(val)-2:]
}

func maskGeneric(val string) string {
	if len(val) <= 4 {
		return "****"
	}
	return val[:2] + "****" + val[len(val)-2:]
}
