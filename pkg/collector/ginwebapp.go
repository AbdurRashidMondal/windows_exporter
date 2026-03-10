package collector

import (
	"log/slog"
	"regexp"
	"strconv"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus-community/windows_exporter/internal/mi"
	"github.com/prometheus-community/windows_exporter/internal/pdh"
	"github.com/prometheus/client_golang/prometheus"
)

const GinWebAppName = "ginwebapp"

// aspNetInstanceRe parses PDH instance names like _LM_W3SVC_1_ROOT_AppName
var aspNetInstanceRe = regexp.MustCompile(`^_LM_W3SVC_(\d+)_ROOT(.*)$`)

type GinWebAppCollector struct {
	logger         *slog.Logger
	aspNetColl     *pdh.Collector
	processColl    *pdh.Collector
	netClrColl     *pdh.Collector
	webServiceColl *pdh.Collector
}

// aspNetValues — ASP.NET Applications Performance Counters (per virtual app path)
type aspNetValues struct {
	Name string

	// Traffic
	RequestsSec           float64 `perfdata:"Requests/Sec"`
	RequestsExecuting     float64 `perfdata:"Requests Executing"`
	RequestsTotal         float64 `perfdata:"Requests Total"`
	RequestsFailed        float64 `perfdata:"Requests Failed"`
	RequestsSucceeded     float64 `perfdata:"Requests Succeeded"`
	RequestsQueued        float64 `perfdata:"Requests Queued"`
	RequestsRejected      float64 `perfdata:"Requests Rejected"`
	RequestsNotFound      float64 `perfdata:"Requests Not Found"`
	RequestsNotAuthorized float64 `perfdata:"Requests Not Authorized"`
	RequestsTimedOut      float64 `perfdata:"Requests Timed Out"`

	// Errors
	ErrorsTotal          float64 `perfdata:"Errors Total/Sec"`
	ErrorsUnhandledTotal float64 `perfdata:"Errors Unhandled During Execution Total"`

	// Latency
	RequestExecutionTime float64 `perfdata:"Request Execution Time"`
	RequestWaitTime      float64 `perfdata:"Request Wait Time"`

	// Cache
	OutputCacheTurnover float64 `perfdata:"Output Cache Turnover Rate"`
	OutputCacheHits     float64 `perfdata:"Output Cache Hits"`
	OutputCacheMisses   float64 `perfdata:"Output Cache Misses"`

	// Runtime
	PipelineInstanceCount float64 `perfdata:"Pipeline Instance Count"`
	SessionsActive        float64 `perfdata:"Sessions Active"`
	SessionsTotal         float64 `perfdata:"Sessions Total"`
	TransactionsTotal     float64 `perfdata:"Transactions Total"`
}

// processValues — Process Performance Counters (filtered for w3wp)
type processValues struct {
	Name string

	PercentProcessorTime float64 `perfdata:"% Processor Time"`
	WorkingSetPrivate    float64 `perfdata:"Working Set - Private"`
	IOReadBytesSec       float64 `perfdata:"IO Read Bytes/sec"`
	IOWriteBytesSec      float64 `perfdata:"IO Write Bytes/sec"`
	IDProcess            float64 `perfdata:"ID Process"`
}

// netClrValues — .NET CLR Memory Performance Counters
type netClrValues struct {
	Name string

	PercentTimeInGC float64 `perfdata:"% Time in GC"`
	BytesInAllHeaps float64 `perfdata:"# Bytes in all Heaps"`
	Gen0Collections float64 `perfdata:"# Gen 0 Collections"`
	Gen1Collections float64 `perfdata:"# Gen 1 Collections"`
	Gen2Collections float64 `perfdata:"# Gen 2 Collections"`
}

// webServiceValues — Web Service Performance Counters (per IIS site, with HTTP method breakdown)
type webServiceValues struct {
	Name string

	// Per-method request totals
	TotalGetRequests    float64 `perfdata:"Total Get Requests"`
	TotalPostRequests   float64 `perfdata:"Total Post Requests"`
	TotalPutRequests    float64 `perfdata:"Total Put Requests"`
	TotalDeleteRequests float64 `perfdata:"Total Delete Requests"`
	TotalHeadRequests   float64 `perfdata:"Total Head Requests"`
	TotalOtherRequests  float64 `perfdata:"Total Other Request Methods"`

	// Site-level health
	CurrentConnections  float64 `perfdata:"Current Connections"`
	TotalBytesReceived  float64 `perfdata:"Total Bytes Received"`
	TotalBytesSent      float64 `perfdata:"Total Bytes Sent"`
	TotalNotFoundErrors float64 `perfdata:"Total Not Found Errors"`
	TotalLockedErrors   float64 `perfdata:"Total Locked Errors"`
	ServiceUptime       float64 `perfdata:"Service Uptime"`
}

func NewGinWebApp() *GinWebAppCollector {
	return &GinWebAppCollector{}
}

func NewGinWebAppWithFlags(_ *kingpin.Application) *GinWebAppCollector {
	return &GinWebAppCollector{}
}

func (c *GinWebAppCollector) GetName() string {
	return GinWebAppName
}

func (c *GinWebAppCollector) Build(logger *slog.Logger, _ *mi.Session) error {
	c.logger = logger
	var err error

	// 1. ASP.NET Applications — per virtual-app-path traffic & runtime metrics
	c.aspNetColl, err = pdh.NewCollector[aspNetValues](
		logger,
		pdh.CounterTypeRaw,
		"ASP.NET Applications",
		pdh.InstancesAll,
	)
	if err != nil {
		// Fallback to versioned name (older IIS setups)
		c.aspNetColl, err = pdh.NewCollector[aspNetValues](
			logger,
			pdh.CounterTypeRaw,
			"ASP.NET v4.0.30319",
			pdh.InstancesAll,
		)
		if err != nil {
			logger.Warn("Failed to initialize ASP.NET Applications collector", "err", err)
		}
	}

	// 2. Process — w3wp worker process CPU/memory/IO
	c.processColl, err = pdh.NewCollector[processValues](
		logger,
		pdh.CounterTypeRaw,
		"Process",
		[]string{"w3wp"},
	)
	if err != nil {
		logger.Warn("Failed to initialize Process collector", "err", err)
	}

	// 3. .NET CLR Memory — GC and heap stats for w3wp instances
	c.netClrColl, err = pdh.NewCollector[netClrValues](
		logger,
		pdh.CounterTypeRaw,
		".NET CLR Memory",
		[]string{"w3wp"},
	)
	if err != nil {
		logger.Warn("Failed to initialize .NET CLR collector", "err", err)
	}

	// 4. Web Service — per-site metrics with HTTP method breakdown
	c.webServiceColl, err = pdh.NewCollector[webServiceValues](
		logger,
		pdh.CounterTypeRaw,
		"Web Service",
		pdh.InstancesAll,
	)
	if err != nil {
		logger.Warn("Failed to initialize Web Service collector", "err", err)
	}

	return nil
}

func (c *GinWebAppCollector) Close() error {
	if c.aspNetColl != nil {
		c.aspNetColl.Close()
	}
	if c.processColl != nil {
		c.processColl.Close()
	}
	if c.netClrColl != nil {
		c.netClrColl.Close()
	}
	if c.webServiceColl != nil {
		c.webServiceColl.Close()
	}
	return nil
}

func (c *GinWebAppCollector) Collect(ch chan<- prometheus.Metric) error {
	c.collectAspNet(ch)
	c.collectProcess(ch)
	c.collectNetClr(ch)
	c.collectWebService(ch)
	return nil
}

// collectAspNet emits per-virtual-app-path metrics from the ASP.NET Applications PDH object.
// Labels: site_id (IIS site number), app_path (virtual directory path, e.g. "/GinesysWeb")
func (c *GinWebAppCollector) collectAspNet(ch chan<- prometheus.Metric) {
	if c.aspNetColl == nil {
		return
	}

	var data []aspNetValues
	if err := c.aspNetColl.Collect(&data); err != nil {
		c.logger.Warn("ASP.NET Applications collect error", "err", err)
		return
	}

	for _, d := range data {
		// Skip the aggregate __Total__ instance
		if strings.Contains(strings.ToLower(d.Name), "__total__") {
			continue
		}

		siteID, appPath := parseAspNetInstance(d.Name)
		labels := []string{siteID, appPath}

		// --- Traffic ---
		ch <- metric("requests_per_sec", "Requests per second for the application (Requests/Sec)", prometheus.GaugeValue,
			d.RequestsSec, labels, "site_id", "app_path")
		ch <- metric("requests_executing", "Requests currently executing in the application pipeline", prometheus.GaugeValue,
			d.RequestsExecuting, labels, "site_id", "app_path")
		ch <- metric("requests_total", "Total HTTP requests processed since app started", prometheus.CounterValue,
			d.RequestsTotal, labels, "site_id", "app_path")
		ch <- metric("requests_failed_total", "Total requests that failed", prometheus.CounterValue,
			d.RequestsFailed, labels, "site_id", "app_path")
		ch <- metric("requests_succeeded_total", "Total requests that completed successfully", prometheus.CounterValue,
			d.RequestsSucceeded, labels, "site_id", "app_path")
		ch <- metric("requests_queued", "Requests currently waiting in the pipeline queue", prometheus.GaugeValue,
			d.RequestsQueued, labels, "site_id", "app_path")
		ch <- metric("requests_rejected_total", "Total requests rejected (queue full)", prometheus.CounterValue,
			d.RequestsRejected, labels, "site_id", "app_path")
		ch <- metric("requests_not_found_total", "Total requests rejected with 404 Not Found", prometheus.CounterValue,
			d.RequestsNotFound, labels, "site_id", "app_path")
		ch <- metric("requests_not_authorized_total", "Total requests rejected with 401 Not Authorized", prometheus.CounterValue,
			d.RequestsNotAuthorized, labels, "site_id", "app_path")
		ch <- metric("requests_timed_out_total", "Total requests that timed out", prometheus.CounterValue,
			d.RequestsTimedOut, labels, "site_id", "app_path")

		// --- Errors ---
		ch <- metric("errors_per_sec", "Errors per second (all error types combined)", prometheus.GaugeValue,
			d.ErrorsTotal, labels, "site_id", "app_path")
		ch <- metric("errors_unhandled_total", "Total unhandled exceptions during request execution", prometheus.CounterValue,
			d.ErrorsUnhandledTotal, labels, "site_id", "app_path")

		// --- Latency ---
		ch <- metric("request_execution_time_ms", "Execution time in ms of the most recently completed request", prometheus.GaugeValue,
			d.RequestExecutionTime, labels, "site_id", "app_path")
		ch <- metric("request_wait_time_ms", "Time in ms the most recent request spent waiting in queue", prometheus.GaugeValue,
			d.RequestWaitTime, labels, "site_id", "app_path")

		// --- Cache ---
		ch <- metric("output_cache_hits_total", "Total output cache hits", prometheus.CounterValue,
			d.OutputCacheHits, labels, "site_id", "app_path")
		ch <- metric("output_cache_misses_total", "Total output cache misses", prometheus.CounterValue,
			d.OutputCacheMisses, labels, "site_id", "app_path")
		ch <- metric("output_cache_turnover_rate", "Output cache turnover rate (items removed/sec)", prometheus.GaugeValue,
			d.OutputCacheTurnover, labels, "site_id", "app_path")

		// --- Runtime ---
		ch <- metric("pipeline_instances", "Number of active pipeline instances", prometheus.GaugeValue,
			d.PipelineInstanceCount, labels, "site_id", "app_path")
		ch <- metric("sessions_active", "Number of currently active user sessions", prometheus.GaugeValue,
			d.SessionsActive, labels, "site_id", "app_path")
		ch <- metric("sessions_total", "Total sessions created since app started", prometheus.CounterValue,
			d.SessionsTotal, labels, "site_id", "app_path")
		ch <- metric("transactions_total", "Total transactions processed", prometheus.CounterValue,
			d.TransactionsTotal, labels, "site_id", "app_path")
	}
}

// collectProcess emits per-w3wp-worker-process CPU/memory/IO metrics.
// Labels: process (w3wp instance name), pid
func (c *GinWebAppCollector) collectProcess(ch chan<- prometheus.Metric) {
	if c.processColl == nil {
		return
	}

	var data []processValues
	if err := c.processColl.Collect(&data); err != nil {
		c.logger.Warn("Process collect error", "err", err)
		return
	}

	for _, d := range data {
		pid := formatPID(d.IDProcess)
		labels := []string{d.Name, pid}

		ch <- metric("process_cpu_percent", "CPU utilization percentage of the IIS worker process", prometheus.GaugeValue,
			d.PercentProcessorTime, labels, "process", "pid")
		ch <- metric("process_memory_bytes", "Private working set memory bytes of the IIS worker process", prometheus.GaugeValue,
			d.WorkingSetPrivate, labels, "process", "pid")
		ch <- metric("process_io_read_bytes_sec", "IO read bytes per second for the IIS worker process", prometheus.GaugeValue,
			d.IOReadBytesSec, labels, "process", "pid")
		ch <- metric("process_io_write_bytes_sec", "IO write bytes per second for the IIS worker process", prometheus.GaugeValue,
			d.IOWriteBytesSec, labels, "process", "pid")
	}
}

// collectNetClr emits .NET GC and heap metrics for w3wp processes.
// Labels: process (w3wp instance name)
func (c *GinWebAppCollector) collectNetClr(ch chan<- prometheus.Metric) {
	if c.netClrColl == nil {
		return
	}

	var data []netClrValues
	if err := c.netClrColl.Collect(&data); err != nil {
		c.logger.Warn(".NET CLR collect error", "err", err)
		return
	}

	for _, d := range data {
		if strings.Contains(d.Name, "_Global_") {
			continue
		}

		labels := []string{d.Name}

		ch <- metric("dotnet_gc_time_percent", "Percentage of time spent in garbage collection", prometheus.GaugeValue,
			d.PercentTimeInGC, labels, "process")
		ch <- metric("dotnet_heap_bytes", "Total bytes in all managed heaps", prometheus.GaugeValue,
			d.BytesInAllHeaps, labels, "process")
		ch <- metric("dotnet_gen0_collections_total", "Total Gen 0 garbage collections", prometheus.CounterValue,
			d.Gen0Collections, labels, "process")
		ch <- metric("dotnet_gen1_collections_total", "Total Gen 1 garbage collections", prometheus.CounterValue,
			d.Gen1Collections, labels, "process")
		ch <- metric("dotnet_gen2_collections_total", "Total Gen 2 garbage collections", prometheus.CounterValue,
			d.Gen2Collections, labels, "process")
	}
}

// collectWebService emits per-IIS-site metrics with HTTP method breakdown.
// Labels: site (IIS site name, e.g. "Default Web Site"), method (GET/POST/PUT/DELETE/HEAD/other)
func (c *GinWebAppCollector) collectWebService(ch chan<- prometheus.Metric) {
	if c.webServiceColl == nil {
		return
	}

	var data []webServiceValues
	if err := c.webServiceColl.Collect(&data); err != nil {
		c.logger.Warn("Web Service collect error", "err", err)
		return
	}

	for _, d := range data {
		// Skip the _Total aggregate
		if strings.EqualFold(d.Name, "_Total") {
			continue
		}

		site := d.Name

		// Per-method request totals (use {site, method} labels)
		for _, entry := range []struct {
			method string
			value  float64
		}{
			{"GET", d.TotalGetRequests},
			{"POST", d.TotalPostRequests},
			{"PUT", d.TotalPutRequests},
			{"DELETE", d.TotalDeleteRequests},
			{"HEAD", d.TotalHeadRequests},
			{"other", d.TotalOtherRequests},
		} {
			ch <- metricWith2Labels(
				"site_requests_total",
				"Total HTTP requests to the IIS site broken down by HTTP method",
				prometheus.CounterValue,
				entry.value,
				site, entry.method,
			)
		}

		// Site-level health metrics (single {site} label)
		siteLabelSlice := []string{site}

		ch <- metric("site_connections", "Current open connections to the IIS site", prometheus.GaugeValue,
			d.CurrentConnections, siteLabelSlice, "site")
		ch <- metric("site_bytes_received_total", "Total bytes received by the IIS site", prometheus.CounterValue,
			d.TotalBytesReceived, siteLabelSlice, "site")
		ch <- metric("site_bytes_sent_total", "Total bytes sent by the IIS site", prometheus.CounterValue,
			d.TotalBytesSent, siteLabelSlice, "site")
		ch <- metric("site_not_found_errors_total", "Total 404 Not Found errors from the IIS site", prometheus.CounterValue,
			d.TotalNotFoundErrors, siteLabelSlice, "site")
		ch <- metric("site_locked_errors_total", "Total 423 Locked errors from the IIS site", prometheus.CounterValue,
			d.TotalLockedErrors, siteLabelSlice, "site")
		ch <- metric("site_uptime_seconds", "Seconds since the IIS site was started", prometheus.CounterValue,
			d.ServiceUptime, siteLabelSlice, "site")
	}
}

// metric is a helper that builds and returns a prometheus.Metric.
// labelNames and labelValues must have matching length.
func metric(name, help string, typ prometheus.ValueType, value float64, labelValues []string, labelNames ...string) prometheus.Metric {
	return prometheus.MustNewConstMetric(
		prometheus.NewDesc(
			prometheus.BuildFQName("windows", "ginwebapp", name),
			help,
			labelNames,
			nil,
		),
		typ,
		value,
		labelValues...,
	)
}

// metricWith2Labels is a convenience helper for the common {site, method} pair.
func metricWith2Labels(name, help string, typ prometheus.ValueType, value float64, label1, label2 string) prometheus.Metric {
	return prometheus.MustNewConstMetric(
		prometheus.NewDesc(
			prometheus.BuildFQName("windows", "ginwebapp", name),
			help,
			[]string{"site", "method"},
			nil,
		),
		typ,
		value,
		label1, label2,
	)
}

// parseAspNetInstance extracts the IIS site ID and virtual application path from a
// PDH ASP.NET Applications instance name.
//
// PDH encodes the path as: _LM_W3SVC_{siteID}_ROOT{_sub_path}
// Examples:
//   - "_LM_W3SVC_1_ROOT"              → siteID="1", appPath="/"
//   - "_LM_W3SVC_1_ROOT_GinesysWeb"   → siteID="1", appPath="/GinesysWeb"
//   - "_LM_W3SVC_2_ROOT_GinesysWeb_anc" → siteID="2", appPath="/GinesysWeb/anc"
//
// Note: underscores in original app-path segments are indistinguishable from path
// separators in the encoded name. The decoded path is a best-effort interpretation.
func parseAspNetInstance(name string) (siteID, appPath string) {
	m := aspNetInstanceRe.FindStringSubmatch(name)
	if m == nil {
		// Not in the expected format — return the raw name as-is
		return "unknown", name
	}

	siteID = m[1]
	remainder := m[2] // everything after _ROOT, starts with _ if non-root

	if remainder == "" {
		appPath = "/"
		return
	}

	// remainder looks like "_GinesysWeb" or "_GinesysWeb_anc"
	// Replace leading underscore with nothing, remaining underscores become /
	// i.e. "_GinesysWeb_anc" → "/GinesysWeb/anc"
	appPath = "/" + strings.ReplaceAll(strings.TrimPrefix(remainder, "_"), "_", "/")
	return
}

func formatPID(f float64) string {
	return strconv.FormatUint(uint64(f), 10)
}
