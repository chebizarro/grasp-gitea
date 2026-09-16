package telemetry

import (
	"context"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

const EnvEnabled = "GRASP_OTEL_ENABLED"

type Provider struct{ shutdowns []func(context.Context) error }

func Init(ctx context.Context) (*Provider, error) {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(EnvEnabled)))
	if v != "1" && v != "true" && v != "yes" && v != "on" {
		return nil, nil
	}
	res, err := resource.New(ctx, resource.WithFromEnv(), resource.WithAttributes(semconv.ServiceName("grasp-gitea")))
	if err != nil {
		return nil, err
	}
	te, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(sdktrace.WithResource(res), sdktrace.WithBatcher(te))
	otel.SetTracerProvider(tp)
	me, err := otlpmetrichttp.New(ctx)
	if err != nil {
		return nil, err
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res), sdkmetric.WithReader(sdkmetric.NewPeriodicReader(me)))
	otel.SetMeterProvider(mp)
	le, err := otlploghttp.New(ctx)
	if err != nil {
		return nil, err
	}
	lp := sdklog.NewLoggerProvider(sdklog.WithResource(res), sdklog.WithProcessor(sdklog.NewBatchProcessor(le)))
	global.SetLoggerProvider(lp)
	return &Provider{[]func(context.Context) error{tp.Shutdown, mp.Shutdown, lp.Shutdown}}, nil
}
func (p *Provider) Shutdown(ctx context.Context) {
	if p != nil {
		for i := len(p.shutdowns) - 1; i >= 0; i-- {
			_ = p.shutdowns[i](ctx)
		}
	}
}
func Start(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return otel.Tracer("github.com/sharegap/grasp-gitea").Start(ctx, name, trace.WithAttributes(attrs...))
}
func End(span trace.Span, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	span.End()
}
func TraceTags(ctx context.Context) (string, string) {
	c := propagation.MapCarrier{}
	propagation.TraceContext{}.Inject(ctx, c)
	return c.Get("traceparent"), c.Get("tracestate")
}

var meter = otel.Meter("github.com/sharegap/grasp-gitea")
var triggers, _ = meter.Int64Counter("grasp.hiveci.triggers")
var failures, _ = meter.Int64Counter("grasp.hiveci.failures")
var latency, _ = meter.Float64Histogram("grasp.push_to_trigger.latency", metric.WithUnit("s"))

func RecordTrigger(ctx context.Context, start time.Time, err error) {
	triggers.Add(ctx, 1)
	if err != nil {
		failures.Add(ctx, 1)
	}
	if !start.IsZero() {
		latency.Record(ctx, time.Since(start).Seconds())
	}
}
