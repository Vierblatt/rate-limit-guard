package guard

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	metricsRateLimitHits = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ratelimit_hits_total",
		Help: "Total number of rate limit triggers",
	})
	metricsBlockedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ratelimit_blocked_total",
		Help: "Total number of blocked requests by IP risk",
	})
	metricsBlacklistCount = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ratelimit_blacklist_count",
		Help: "Current number of blacklisted IPs",
	})
	metricsRequestTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ratelimit_request_total",
		Help: "Total number of requests processed",
	})
)

type Metrics struct{}

func NewMetrics() *Metrics { return &Metrics{} }

func (m *Metrics) IncRateLimitHits() { metricsRateLimitHits.Inc() }

func (m *Metrics) IncBlocked() { metricsBlockedTotal.Inc() }

func (m *Metrics) SetBlacklistCount(n int) { metricsBlacklistCount.Set(float64(n)) }

func (m *Metrics) IncRequest() { metricsRequestTotal.Inc() }
