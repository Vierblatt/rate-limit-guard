package guard

import (
	"net/http"
	"strings"

	"github.com/Vierblatt/rate-limit-guard/limiter"
	"github.com/Vierblatt/rate-limit-guard/privacy"
	"github.com/zeromicro/go-zero/rest"
)

func (g *Guard) PrivacyMiddleware() rest.Middleware {
	s := privacy.NewSanitizer(g.config.Privacy)
	tz := privacy.NewTimezoneParser(g.config.Privacy.TimezoneHeader)

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			loc := tz.Parse(r.Header)
			ctx := WithTimezone(r.Context(), loc)

			if g.config.Privacy.Enabled {
				sanitized := s.SanitizeHeaders(r.Header)
				ctx = contextWithSanitizedHeaders(ctx, sanitized)
			}

			next(w, r.WithContext(ctx))
		}
	}
}

func (g *Guard) IPRiskMiddleware() rest.Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ip := extractIP(r)

			if g.ipRisk.IsWhitelisted(ip) {
				next(w, r)
				return
			}

			if !g.config.IPRisk.Enabled {
				next(w, r)
				return
			}

			blocked, err := g.blacklist.IsBlocked(ip)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if blocked {
				g.metrics.IncBlocked()
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			country := g.ipRisk.CountryFrom(r.Header)
			next(w, r.WithContext(WithCountry(r.Context(), country)))
		}
	}
}

func (g *Guard) RateLimitMiddleware() rest.Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ip := extractIP(r)
			role := detectRole(r)
			id := resolveID(r, role)

			ctx := WithRole(r.Context(), role)
			ctx = WithCountry(ctx, g.ipRisk.CountryFrom(r.Header))
			r = r.WithContext(ctx)

			if !g.enforceRateLimit(w, r, ip, role, id) {
				return
			}

			next(w, r)
		}
	}
}

func (g *Guard) Middleware() rest.Middleware {
	s := privacy.NewSanitizer(g.config.Privacy)
	tz := privacy.NewTimezoneParser(g.config.Privacy.TimezoneHeader)

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ip := extractIP(r)
			role := detectRole(r)
			id := resolveID(r, role)

			loc := tz.Parse(r.Header)
			ctx := WithTimezone(r.Context(), loc)
			ctx = WithRole(ctx, role)
			ctx = WithRegion(ctx, ip)
			ctx = WithCountry(ctx, g.ipRisk.CountryFrom(r.Header))

			if g.config.Privacy.Enabled {
				sanitized := s.SanitizeHeaders(r.Header)
				ctx = contextWithSanitizedHeaders(ctx, sanitized)
			}

			r = r.WithContext(ctx)

			if g.ipRisk.IsWhitelisted(ip) {
				next(w, r)
				return
			}

			if g.config.IPRisk.Enabled {
				blocked, err := g.blacklist.IsBlocked(ip)
				if err != nil {
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}
				if blocked {
					g.metrics.IncBlocked()
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
			}

			if !g.enforceRateLimit(w, r, ip, role, id) {
				return
			}

			next(w, r)
		}
	}
}

// enforceRateLimit applies the sliding window quota, tightened by the caller's
// region risk level. It reports whether the request may proceed; on rejection it
// has already written the response.
func (g *Guard) enforceRateLimit(w http.ResponseWriter, r *http.Request, ip string, role limiter.Role, id string) bool {
	// A whitelisted IP is an internal caller: exempt from limiting entirely, so
	// the composed middleware chain and the standalone limiter agree.
	if g.ipRisk.IsWhitelisted(ip) {
		return true
	}

	country := GetCountry(r.Context())
	limit := g.ipRisk.Quota(country, g.limiter.LimitFor(role))

	allowed, err := g.limiter.AllowN(role, id, limit)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return false
	}

	g.metrics.IncRequest()

	if !allowed {
		g.metrics.IncRateLimitHits()
		if g.config.IPRisk.Enabled {
			if blocked, blErr := g.blacklist.RecordFail(ip); blErr == nil && blocked {
				if size, sizeErr := g.blacklist.Size(); sizeErr == nil {
					g.metrics.SetBlacklistCount(size)
				}
			}
		}
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return false
	}

	return true
}

func extractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	idx := strings.LastIndex(r.RemoteAddr, ":")
	if idx > 0 {
		return r.RemoteAddr[:idx]
	}
	return r.RemoteAddr
}

func detectRole(r *http.Request) limiter.Role {
	if r.Header.Get("X-Admin") != "" {
		return limiter.RoleAdmin
	}
	if r.Header.Get("X-User-Id") != "" {
		return limiter.RoleUser
	}
	return limiter.RoleGuest
}

// resolveID returns the bucket key for role. detectRole only selects a role when
// its identifying header is present, so the Get calls below never come back empty.
func resolveID(r *http.Request, role limiter.Role) string {
	switch role {
	case limiter.RoleAdmin:
		return r.Header.Get("X-Admin")
	case limiter.RoleUser:
		return r.Header.Get("X-User-Id")
	default:
		return extractIP(r)
	}
}
