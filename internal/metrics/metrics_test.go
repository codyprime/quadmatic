package metrics

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"

	"quadmatic/internal/apply"
)

func scrapeMetrics(t *testing.T, h http.Handler) (string, map[string]*dto.MetricFamily) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	body := rec.Body.String()
	parser := expfmt.TextParser{}
	families, err := parser.TextToMetricFamilies(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parse Prometheus exposition: %v\nbody:\n%s", err, body)
	}
	return body, families
}

func findMetric(t *testing.T, families map[string]*dto.MetricFamily, name string, wantLabels map[string]string) (*dto.Metric, bool) {
	t.Helper()
	fam, ok := families[name]
	if !ok {
		return nil, false
	}
	for _, m := range fam.GetMetric() {
		if labelsMatch(m.GetLabel(), wantLabels) {
			return m, true
		}
	}
	return nil, false
}

func labelsMatch(pairs []*dto.LabelPair, want map[string]string) bool {
	if len(pairs) != len(want) {
		return false
	}
	for _, lp := range pairs {
		v, ok := want[lp.GetName()]
		if !ok || v != lp.GetValue() {
			return false
		}
	}
	return true
}

func assertGaugeValue(t *testing.T, families map[string]*dto.MetricFamily, name string, labels map[string]string, want float64) {
	t.Helper()
	if fam, ok := families[name]; ok && fam.GetType() != dto.MetricType_GAUGE {
		t.Fatalf("metric %s type = %v, want GAUGE", name, fam.GetType())
	}
	m, ok := findMetric(t, families, name, labels)
	if !ok {
		t.Fatalf("metric %s with labels %v not found", name, labels)
	}
	got := m.GetGauge().GetValue()
	if got != want {
		t.Fatalf("metric %s%v = %v, want %v", name, labels, got, want)
	}
}

func assertCounterValue(t *testing.T, families map[string]*dto.MetricFamily, name string, labels map[string]string, want float64) {
	t.Helper()
	if fam, ok := families[name]; ok && fam.GetType() != dto.MetricType_COUNTER {
		t.Fatalf("metric %s type = %v, want COUNTER", name, fam.GetType())
	}
	m, ok := findMetric(t, families, name, labels)
	if !ok {
		t.Fatalf("metric %s with labels %v not found", name, labels)
	}
	got := m.GetCounter().GetValue()
	if got != want {
		t.Fatalf("metric %s%v = %v, want %v", name, labels, got, want)
	}
}

func TestRecorderExportsAllSpecMetrics(t *testing.T) {
	rec := NewRecorder("services-02")

	// 1. Record a successful reconcile with drift and a non-active unit.
	rec.RecordResult(&apply.Result{
		AppliedSHA:           "sha1111",
		DriftDetected:        true,
		ManagedUnitsRootless: 3,
		ManagedUnitsRootful:  1,
		FailedUnits: []apply.UnitStatus{
			{Scope: "openwebui", Unit: "openwebui.service", ActiveState: "failed"},
		},
		Duration: 1500 * time.Millisecond,
	}, nil)

	body, families := scrapeMetrics(t, rec.Handler())

	// Ensure dedicated registry does not export global Go runtime metrics.
	if _, hasGoMetric := families["go_goroutines"]; hasGoMetric {
		t.Fatalf("dedicated registry unexpectedly exported go_goroutines:\n%s", body)
	}

	tsMetric, ok := findMetric(t, families, "quadmatic_last_sync_timestamp_seconds", nil)
	if !ok {
		t.Fatalf("missing quadmatic_last_sync_timestamp_seconds")
	}
	if ts := tsMetric.GetGauge().GetValue(); ts <= 0 {
		t.Fatalf("quadmatic_last_sync_timestamp_seconds = %v, want > 0", ts)
	}

	assertGaugeValue(t, families, "quadmatic_last_sync_success", nil, 1)
	assertGaugeValue(t, families, "quadmatic_sync_duration_seconds", nil, 1.5)
	assertGaugeValue(t, families, "quadmatic_applied_info", map[string]string{"sha": "sha1111", "hostname": "services-02"}, 1)
	assertGaugeValue(t, families, "quadmatic_managed_units", map[string]string{"scope": "rootless"}, 3)
	assertGaugeValue(t, families, "quadmatic_managed_units", map[string]string{"scope": "rootful"}, 1)
	assertGaugeValue(t, families, "quadmatic_failed_units", map[string]string{"user": "openwebui", "unit": "openwebui.service"}, 1)
	assertGaugeValue(t, families, "quadmatic_drift_detected", nil, 1)
	assertCounterValue(t, families, "quadmatic_rollbacks_total", nil, 0)

	// 2. Record a second successful reconcile on a new SHA with recovered unit and no drift.
	rec.RecordResult(&apply.Result{
		AppliedSHA:           "sha2222",
		DriftDetected:        false,
		ManagedUnitsRootless: 4,
		ManagedUnitsRootful:  2,
		FailedUnits:          nil,
		Duration:             500 * time.Millisecond,
	}, nil)

	_, families = scrapeMetrics(t, rec.Handler())

	if _, stale := findMetric(t, families, "quadmatic_applied_info", map[string]string{"sha": "sha1111", "hostname": "services-02"}); stale {
		t.Fatalf("stale quadmatic_applied_info labelset for sha1111 lingered after reset")
	}
	assertGaugeValue(t, families, "quadmatic_applied_info", map[string]string{"sha": "sha2222", "hostname": "services-02"}, 1)

	if fam, hasFailed := families["quadmatic_failed_units"]; hasFailed && len(fam.GetMetric()) > 0 {
		t.Fatalf("recovered failed unit lingered in quadmatic_failed_units: %+v", fam.GetMetric())
	}
	assertGaugeValue(t, families, "quadmatic_drift_detected", nil, 0)
	assertGaugeValue(t, families, "quadmatic_managed_units", map[string]string{"scope": "rootless"}, 4)
	assertGaugeValue(t, families, "quadmatic_managed_units", map[string]string{"scope": "rootful"}, 2)

	// 3. Record a failed and rolled-back reconcile.
	rec.RecordResult(&apply.Result{
		AppliedSHA:           "sha2222",
		DriftDetected:        false,
		RolledBack:           true,
		FailedStage:          "apply",
		ManagedUnitsRootless: 4,
		ManagedUnitsRootful:  2,
		Duration:             2250 * time.Millisecond,
	}, errors.New("start verify timed out"))

	_, families = scrapeMetrics(t, rec.Handler())

	assertGaugeValue(t, families, "quadmatic_last_sync_success", nil, 0)
	assertGaugeValue(t, families, "quadmatic_sync_duration_seconds", nil, 2.25)
	assertGaugeValue(t, families, "quadmatic_applied_info", map[string]string{"sha": "sha2222", "hostname": "services-02"}, 1)
	assertCounterValue(t, families, "quadmatic_rollbacks_total", nil, 1)
	assertCounterValue(t, families, "quadmatic_reconcile_errors_total", map[string]string{"stage": "apply"}, 1)
}

func TestRecorderHandlesNilResultError(t *testing.T) {
	rec := NewRecorder("node-01")
	rec.RecordResult(nil, errors.New("unexpected panic/nil result"))

	_, families := scrapeMetrics(t, rec.Handler())
	assertGaugeValue(t, families, "quadmatic_last_sync_success", nil, 0)
	assertGaugeValue(t, families, "quadmatic_sync_duration_seconds", nil, 0)
	assertGaugeValue(t, families, "quadmatic_drift_detected", nil, 0)
	assertCounterValue(t, families, "quadmatic_reconcile_errors_total", map[string]string{"stage": "unknown"}, 1)
}

func TestRecorderPreservesUnitMetricsAcrossPreApplyErrors(t *testing.T) {
	rec := NewRecorder("services-02")

	// Baseline successful reconcile with active unit counts and one failed unit.
	rec.RecordResult(&apply.Result{
		AppliedSHA:           "sha-good",
		ManagedUnitsRootless: 3,
		ManagedUnitsRootful:  1,
		FailedUnits: []apply.UnitStatus{
			{Scope: "openwebui", Unit: "openwebui.service", ActiveState: "failed"},
		},
		Duration: 1 * time.Second,
	}, nil)

	for _, stage := range []string{"fetch", "verify", "validate"} {
		rec.RecordResult(&apply.Result{
			AppliedSHA:           "sha-good",
			FailedStage:          stage,
			ManagedUnitsRootless: 0,
			ManagedUnitsRootful:  0,
			FailedUnits:          nil,
			Duration:             250 * time.Millisecond,
		}, errors.New(stage+" failed"))

		_, families := scrapeMetrics(t, rec.Handler())
		assertGaugeValue(t, families, "quadmatic_last_sync_success", nil, 0)
		assertGaugeValue(t, families, "quadmatic_managed_units", map[string]string{"scope": "rootless"}, 3)
		assertGaugeValue(t, families, "quadmatic_managed_units", map[string]string{"scope": "rootful"}, 1)
		assertGaugeValue(t, families, "quadmatic_failed_units", map[string]string{"user": "openwebui", "unit": "openwebui.service"}, 1)
		assertGaugeValue(t, families, "quadmatic_applied_info", map[string]string{"sha": "sha-good", "hostname": "services-02"}, 1)
		assertCounterValue(t, families, "quadmatic_reconcile_errors_total", map[string]string{"stage": stage}, 1)
	}

	// An "apply" stage failure with updated unit statuses DOES refresh unit metrics.
	rec.RecordResult(&apply.Result{
		AppliedSHA:           "sha-good",
		FailedStage:          "apply",
		RolledBack:           true,
		ManagedUnitsRootless: 2,
		ManagedUnitsRootful:  0,
		FailedUnits:          nil,
		Duration:             500 * time.Millisecond,
	}, errors.New("apply failed"))

	_, families := scrapeMetrics(t, rec.Handler())
	assertGaugeValue(t, families, "quadmatic_managed_units", map[string]string{"scope": "rootless"}, 2)
	assertGaugeValue(t, families, "quadmatic_managed_units", map[string]string{"scope": "rootful"}, 0)
	if fam, ok := families["quadmatic_failed_units"]; ok && len(fam.GetMetric()) > 0 {
		t.Fatalf("expected failed_units cleared on post-validate failure, got %+v", fam.GetMetric())
	}

	// Post-validate failures (users/files/net/apply rollback) keep reporting failed units
	// whenever Result.FailedUnits is populated.
	for _, tc := range []struct {
		stage      string
		rolledBack bool
	}{
		{stage: "users", rolledBack: false},
		{stage: "net", rolledBack: false},
		{stage: "apply", rolledBack: true},
		{stage: "rollback", rolledBack: true},
	} {
		rec.RecordResult(&apply.Result{
			AppliedSHA:           "sha-good",
			FailedStage:          tc.stage,
			RolledBack:           tc.rolledBack,
			ManagedUnitsRootless: 2,
			ManagedUnitsRootful:  1,
			FailedUnits: []apply.UnitStatus{
				{Scope: "openwebui", Unit: "open-webui.service", ActiveState: "failed"},
				{Scope: "caddy", Unit: "caddy.service", ActiveState: "inactive"},
			},
			Duration: 300 * time.Millisecond,
		}, errors.New(tc.stage+" failed"))

		_, families = scrapeMetrics(t, rec.Handler())
		assertGaugeValue(t, families, "quadmatic_last_sync_success", nil, 0)
		assertGaugeValue(t, families, "quadmatic_failed_units", map[string]string{"user": "openwebui", "unit": "open-webui.service"}, 1)
		assertGaugeValue(t, families, "quadmatic_failed_units", map[string]string{"user": "caddy", "unit": "caddy.service"}, 1)
	}
}

func TestNewServerRejectsWildcardBind(t *testing.T) {
	rec := NewRecorder("services-02")

	badAddrs := []string{
		"",
		"0.0.0.0:9100",
		":9100",
		"[::]:9100",
		"[::ffff:0.0.0.0]:9100",
		"localhost:9100",
		"127.0.0.1:0",
		"not-an-addr",
	}
	for _, addr := range badAddrs {
		srv, err := NewServer(addr, rec)
		if err == nil {
			t.Fatalf("NewServer(%q, rec) unexpectedly succeeded: %+v", addr, srv)
		}
	}

	if _, err := NewServer("127.0.0.1:9100", nil); err == nil {
		t.Fatalf("NewServer with nil recorder unexpectedly succeeded")
	}

	goodAddrs := []string{
		"127.0.0.1:9100",
		"10.0.3.12:9100",
		"[fd00::1]:9100",
	}
	for _, addr := range goodAddrs {
		srv, err := NewServer(addr, rec)
		if err != nil {
			t.Fatalf("NewServer(%q, rec) failed: %v", addr, err)
		}
		if srv.Addr != addr {
			t.Fatalf("srv.Addr = %q, want %q", srv.Addr, addr)
		}
		if srv.ReadHeaderTimeout <= 0 {
			t.Fatalf("srv.ReadHeaderTimeout = %v, want > 0", srv.ReadHeaderTimeout)
		}
	}

	srv, err := NewServer("127.0.0.1:9100", rec)
	if err != nil {
		t.Fatalf("NewServer(127.0.0.1:9100, rec) failed: %v", err)
	}

	rec.RecordResult(&apply.Result{AppliedSHA: "abc123", ManagedUnitsRootless: 1}, nil)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	srv.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /metrics status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "quadmatic_last_sync_success 1") {
		t.Fatalf("expected quadmatic_last_sync_success 1 in response:\n%s", w.Body.String())
	}

	postReq := httptest.NewRequest(http.MethodPost, "/metrics", nil)
	postW := httptest.NewRecorder()
	srv.Handler.ServeHTTP(postW, postReq)
	if postW.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /metrics status = %d, want %d", postW.Code, http.StatusMethodNotAllowed)
	}

	otherReq := httptest.NewRequest(http.MethodGet, "/", nil)
	otherW := httptest.NewRecorder()
	srv.Handler.ServeHTTP(otherW, otherReq)
	if otherW.Code != http.StatusNotFound {
		t.Fatalf("GET / status = %d, want %d", otherW.Code, http.StatusNotFound)
	}
}

func TestRecorderConcurrentRecordAndScrape(t *testing.T) {
	rec := NewRecorder("services-02")
	h := rec.Handler()

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				rec.RecordResult(&apply.Result{
					AppliedSHA:           "sha-concurrent",
					ManagedUnitsRootless: 2,
					ManagedUnitsRootful:  1,
					FailedUnits: []apply.UnitStatus{
						{Scope: "app", Unit: "app.service", ActiveState: "failed"},
					},
					Duration: 100 * time.Millisecond,
				}, nil)
			}
		}(i)
	}

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, req)
				if w.Code != http.StatusOK {
					t.Errorf("concurrent GET /metrics status = %d", w.Code)
					return
				}
			}
		}()
	}

	wg.Wait()
}
