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

			next(w, r)
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
			r = r.WithContext(ctx)

			allowed, err := g.limiter.Allow(role, id)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}

			g.metrics.IncRequest()

			if !allowed {
				g.metrics.IncRateLimitHits()
				blocked, blErr := g.blacklist.RecordFail(ip)
				if blErr == nil && blocked {
					g.metrics.SetBlacklistCount(1)
				}
				http.Error(w, "too many requests", http.StatusTooManyRequests)
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

			allowed, err := g.limiter.Allow(role, id)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}

			g.metrics.IncRequest()

			if !allowed {
				g.metrics.IncRateLimitHits()
				if g.config.IPRisk.Enabled {
					blocked, blErr := g.blacklist.RecordFail(ip)
					if blErr == nil && blocked {
						g.metrics.SetBlacklistCount(1)
					}
				}
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}

			next(w, r)
		}
	}
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

func resolveID(r *http.Request, role limiter.Role) string {
	switch role {
	case limiter.RoleAdmin:
		if id := r.Header.Get("X-Admin"); id != "" {
			return id
		}
		return "admin"
	case limiter.RoleUser:
		if id := r.Header.Get("X-User-Id"); id != "" {
			return id
		}
		return r.Header.Get("Authorization")
	default:
		return extractIP(r)
	}
}
