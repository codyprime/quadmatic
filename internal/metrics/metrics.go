package metrics

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"quadmatic/internal/apply"
	"quadmatic/internal/config"
)

// Recorder tracks reconciliation outcomes in a dedicated Prometheus registry.
type Recorder struct {
	mu       sync.RWMutex
	hostname string
	registry *prometheus.Registry

	lastSyncTimestamp    prometheus.Gauge
	lastSyncSuccess      prometheus.Gauge
	syncDurationSeconds  prometheus.Gauge
	appliedInfo          *prometheus.GaugeVec
	managedUnits         *prometheus.GaugeVec
	failedUnits          *prometheus.GaugeVec
	driftDetected        prometheus.Gauge
	rollbacksTotal       prometheus.Counter
	reconcileErrorsTotal *prometheus.CounterVec
}

// NewRecorder constructs a Recorder backed by an isolated prometheus.NewRegistry.
func NewRecorder(hostname string) *Recorder {
	reg := prometheus.NewRegistry()

	r := &Recorder{
		hostname: hostname,
		registry: reg,
		lastSyncTimestamp: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "quadmatic_last_sync_timestamp_seconds",
			Help: "Unix timestamp of the last completed reconciliation attempt.",
		}),
		lastSyncSuccess: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "quadmatic_last_sync_success",
			Help: "Whether the last reconciliation attempt succeeded (1) or failed (0).",
		}),
		syncDurationSeconds: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "quadmatic_sync_duration_seconds",
			Help: "Duration in seconds of the last reconciliation attempt.",
		}),
		appliedInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "quadmatic_applied_info",
			Help: "Currently applied Git commit SHA and hostname (value is always 1).",
		}, []string{"sha", "hostname"}),
		managedUnits: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "quadmatic_managed_units",
			Help: "Number of managed systemd units by scope.",
		}, []string{"scope"}),
		failedUnits: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "quadmatic_failed_units",
			Help: "Managed systemd units that are not active (value is 1).",
		}, []string{"user", "unit"}),
		driftDetected: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "quadmatic_drift_detected",
			Help: "Whether out-of-band drift was detected on the last reconciliation tick (1 or 0).",
		}),
		rollbacksTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "quadmatic_rollbacks_total",
			Help: "Total number of reconciliation rollbacks executed.",
		}),
		reconcileErrorsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "quadmatic_reconcile_errors_total",
			Help: "Total number of reconciliation errors by stage.",
		}, []string{"stage"}),
	}

	reg.MustRegister(
		r.lastSyncTimestamp,
		r.lastSyncSuccess,
		r.syncDurationSeconds,
		r.appliedInfo,
		r.managedUnits,
		r.failedUnits,
		r.driftDetected,
		r.rollbacksTotal,
		r.reconcileErrorsTotal,
	)

	return r
}

// RecordResult updates all reconciliation metrics atomically for a completed Reconcile pass.
func (r *Recorder) RecordResult(res *apply.Result, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.lastSyncTimestamp.SetToCurrentTime()
	// Reset dynamic-label vectors so stale commit SHAs and recovered units do not linger.
	r.appliedInfo.Reset()
	r.failedUnits.Reset()

	if err != nil {
		r.lastSyncSuccess.Set(0)
	} else {
		r.lastSyncSuccess.Set(1)
	}

	if res != nil {
		r.syncDurationSeconds.Set(res.Duration.Seconds())
		if res.AppliedSHA != "" {
			r.appliedInfo.WithLabelValues(res.AppliedSHA, r.hostname).Set(1)
		}
		r.managedUnits.WithLabelValues("rootless").Set(float64(res.ManagedUnitsRootless))
		r.managedUnits.WithLabelValues("rootful").Set(float64(res.ManagedUnitsRootful))
		for _, fu := range res.FailedUnits {
			r.failedUnits.WithLabelValues(fu.Scope, fu.Unit).Set(1)
		}
		if res.DriftDetected {
			r.driftDetected.Set(1)
		} else {
			r.driftDetected.Set(0)
		}
		if res.RolledBack {
			r.rollbacksTotal.Inc()
		}
	} else {
		r.syncDurationSeconds.Set(0)
		r.driftDetected.Set(0)
	}

	if err != nil {
		stage := "unknown"
		if res != nil && res.FailedStage != "" {
			stage = res.FailedStage
		}
		r.reconcileErrorsTotal.WithLabelValues(stage).Inc()
	}
}

// Handler returns a read-only HTTP handler serving the isolated Prometheus registry.
func (r *Recorder) Handler() http.Handler {
	promHandler := promhttp.HandlerFor(r.registry, promhttp.HandlerOpts{})
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.RLock()
		defer r.mu.RUnlock()
		promHandler.ServeHTTP(w, req)
	})
}

// NewServer constructs a read-only HTTP server serving /metrics on an explicit non-wildcard IP:port.
func NewServer(listenAddr string, rec *Recorder) (*http.Server, error) {
	if rec == nil {
		return nil, errors.New("metrics recorder must not be nil")
	}
	if strings.TrimSpace(listenAddr) == "" {
		return nil, errors.New("metrics listen address must not be empty")
	}
	if err := config.ValidateListenAddr(listenAddr); err != nil {
		return nil, fmt.Errorf("invalid metrics listen address: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("GET /metrics", rec.Handler())

	return &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}, nil
}
