package service

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

type ObservabilityService struct {
	registry          *prometheus.Registry
	httpDuration      *prometheus.HistogramVec
	httpRequests      *prometheus.CounterVec
	authzDuration     *prometheus.HistogramVec
	authzCacheHits    prometheus.Counter
	authzCacheMisses  prometheus.Counter
	dbDuration        *prometheus.HistogramVec
	dbErrors          *prometheus.CounterVec
	activeUsers       prometheus.Gauge
	activeTenants     prometheus.Gauge
	tokenIssued       *prometheus.CounterVec
	tokenRevoked      *prometheus.CounterVec
	loginAttempts     *prometheus.CounterVec
	mfaChallenges     *prometheus.CounterVec
	otelTracerProvider *sdktrace.TracerProvider
}

func NewObservabilityService(serviceName string) (*ObservabilityService, error) {
	registry := prometheus.NewRegistry()

	o := &ObservabilityService{
		registry: registry,
		httpDuration: promauto.With(registry).NewHistogramVec(prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request latency in seconds",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "path", "status"}),
		httpRequests: promauto.With(registry).NewCounterVec(prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		}, []string{"method", "path", "status"}),
		authzDuration: promauto.With(registry).NewHistogramVec(prometheus.HistogramOpts{
			Name:    "authz_check_duration_seconds",
			Help:    "Authorization check latency in seconds",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
		}, []string{"result", "matched_by"}),
		authzCacheHits: promauto.With(registry).NewCounter(prometheus.CounterOpts{
			Name: "authz_cache_hits_total",
			Help: "Total number of authorization cache hits",
		}),
		authzCacheMisses: promauto.With(registry).NewCounter(prometheus.CounterOpts{
			Name: "authz_cache_misses_total",
			Help: "Total number of authorization cache misses",
		}),
		dbDuration: promauto.With(registry).NewHistogramVec(prometheus.HistogramOpts{
			Name:    "db_query_duration_seconds",
			Help:    "Database query latency in seconds",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
		}, []string{"operation", "table", "status"}),
		dbErrors: promauto.With(registry).NewCounterVec(prometheus.CounterOpts{
			Name: "db_errors_total",
			Help: "Total number of database errors",
		}, []string{"operation", "table", "error"}),
		activeUsers: promauto.With(registry).NewGauge(prometheus.GaugeOpts{
			Name: "active_users",
			Help: "Number of currently active users",
		}),
		activeTenants: promauto.With(registry).NewGauge(prometheus.GaugeOpts{
			Name: "active_tenants",
			Help: "Number of active tenants",
		}),
		tokenIssued: promauto.With(registry).NewCounterVec(prometheus.CounterOpts{
			Name: "tokens_issued_total",
			Help: "Total number of tokens issued",
		}, []string{"type"}), // access, refresh, id_token
		tokenRevoked: promauto.With(registry).NewCounterVec(prometheus.CounterOpts{
			Name: "tokens_revoked_total",
			Help: "Total number of tokens revoked",
		}, []string{"type"}),
		loginAttempts: promauto.With(registry).NewCounterVec(prometheus.CounterOpts{
			Name: "login_attempts_total",
			Help: "Total number of login attempts",
		}, []string{"result"}), // success, failure, locked
		mfaChallenges: promauto.With(registry).NewCounterVec(prometheus.CounterOpts{
			Name: "mfa_challenges_total",
			Help: "Total number of MFA challenges",
		}, []string{"type", "result"}), // totp, webauthn, backup_code / success, failure
	}

	// Initialize OpenTelemetry
	if err := o.initOpenTelemetry(serviceName); err != nil {
		return nil, fmt.Errorf("failed to initialize OpenTelemetry: %w", err)
	}

	return o, nil
}

func (o *ObservabilityService) initOpenTelemetry(serviceName string) error {
	exporter, err := otlptracehttp.New(context.Background(),
		otlptracehttp.WithEndpoint("localhost:4318"),
		otlptracehttp.WithInsecure(),
	)
	if err != nil {
		return err
	}

	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceName("hoviyat"),
			semconv.ServiceVersion("1.0.0"),
		),
	)
	if err != nil {
		return err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	o.otelTracerProvider = tp
	return nil
}

func (o *ObservabilityService) RecordHTTPRequest(method, path string, status int, duration time.Duration) {
	statusStr := fmt.Sprintf("%d", status)
	o.httpDuration.WithLabelValues(method, path, statusStr).Observe(duration.Seconds())
	o.httpRequests.WithLabelValues(method, path, fmt.Sprintf("%d", status)).Inc()
}

func (o *ObservabilityService) RecordAuthzCheck(result, matchedBy string, duration time.Duration) {
	o.authzDuration.WithLabelValues(result, matchedBy).Observe(duration.Seconds())
}

func (o *ObservabilityService) RecordCacheHit() {
	o.authzCacheHits.Inc()
}

func (o *ObservabilityService) RecordCacheMiss() {
	o.authzCacheMisses.Inc()
}

func (o *ObservabilityService) RecordDBQuery(operation, table string, duration time.Duration, err error) {
	status := "success"
	if err != nil {
		status = "error"
		o.dbErrors.WithLabelValues("query", "unknown", err.Error()).Inc()
	}
	o.dbDuration.WithLabelValues("query", "unknown", status).Observe(duration.Seconds())
}

func (o *ObservabilityService) RecordTokenIssued(tokenType string) {
	o.tokenIssued.WithLabelValues(tokenType).Inc()
}

func (o *ObservabilityService) RecordTokenRevoked(tokenType string) {
	o.tokenRevoked.WithLabelValues(tokenType).Inc()
}

func (o *ObservabilityService) RecordLoginAttempt(success bool) {
	result := "success"
	if !success {
		result = "failure"
	}
	o.loginAttempts.WithLabelValues(result).Inc()
}

func (o *ObservabilityService) RecordMFAChallenge(mfaType, result string) {
	o.mfaChallenges.WithLabelValues(result, mfaType).Inc()
}

func (o *ObservabilityService) SetActiveUsers(count int) {
	o.activeUsers.Set(float64(count))
}

func (o *ObservabilityService) SetActiveTenants(count int) {
	o.activeTenants.Set(float64(count))
}

func (o *ObservabilityService) MetricsHandler() http.Handler {
	return promhttp.HandlerFor(o.registry, promhttp.HandlerOpts{})
}

func (o *ObservabilityService) Shutdown(ctx context.Context) error {
	if o.otelTracerProvider != nil {
		return o.otelTracerProvider.Shutdown(ctx)
	}
	return nil
}

func (o *ObservabilityService) RecordRuntimeMetrics() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	// Could add custom metrics for GC, heap, etc.
	_ = m
}