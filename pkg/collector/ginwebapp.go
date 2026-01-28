package collector

import (
	"log/slog"
	"strconv"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus-community/windows_exporter/internal/mi"
	"github.com/prometheus-community/windows_exporter/internal/pdh"
	"github.com/prometheus/client_golang/prometheus"
)

const GinWebAppName = "ginwebapp"

type GinWebAppCollector struct {
	logger      *slog.Logger
	aspNetColl  *pdh.Collector
	processColl *pdh.Collector
	netClrColl  *pdh.Collector
}

// ASP.NET Applications Performance Counters
type aspNetValues struct {
	Name string

	RequestsSec         float64 `perfdata:"Requests/Sec"`
	RequestsExecuting   float64 `perfdata:"Requests Executing"`
	RequestsTotal       float64 `perfdata:"Requests Total"`
	ErrorsTotal         float64 `perfdata:"Errors Total/Sec"`
	OutputCacheTurnover float64 `perfdata:"Output Cache Turnover Rate"`
}

// Process Performance Counters (filtered for w3wp)
type processValues struct {
	Name string

	PercentProcessorTime float64 `perfdata:"% Processor Time"`
	WorkingSetPrivate    float64 `perfdata:"Working Set - Private"`
	IOReadBytesSec       float64 `perfdata:"IO Read Bytes/sec"`
	IOWriteBytesSec      float64 `perfdata:"IO Write Bytes/sec"`
	IDProcess            float64 `perfdata:"ID Process"`
}

// .NET CLR Memory Performance Counters
type netClrValues struct {
	Name string

	PercentTimeInGC float64 `perfdata:"% Time in GC"`
	BytesInAllHeaps float64 `perfdata:"# Bytes in all Heaps"`
	Gen0Collections float64 `perfdata:"# Gen 0 Collections"`
	Gen1Collections float64 `perfdata:"# Gen 1 Collections"`
	Gen2Collections float64 `perfdata:"# Gen 2 Collections"`
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

	// 1. Initialize ASP.NET Applications Collector
	// This gives us "per path" traffic metrics
	c.aspNetColl, err = pdh.NewCollector[aspNetValues](
		logger,
		pdh.CounterTypeRaw,
		"ASP.NET Applications", // Generic object for per-app metrics
		pdh.InstancesAll,
	)
	if err != nil {
		// Try versioned name if generic fails
		c.aspNetColl, err = pdh.NewCollector[aspNetValues](
			logger,
			pdh.CounterTypeRaw,
			"ASP.NET v4.0.30319",
			pdh.InstancesAll,
		)
		if err != nil {
			logger.Warn("Failed to initialize ASP.NET collector", "err", err)
		}
	}

	// 2. Initialize Process Collector
	// We specifically target w3wp for IIS worker processes
	c.processColl, err = pdh.NewCollector[processValues](
		logger,
		pdh.CounterTypeRaw,
		"Process",
		[]string{"w3wp"},
	)
	if err != nil {
		logger.Warn("Failed to initialize Process collector", "err", err)
	}

	// 3. Initialize .NET CLR Memory Collector
	c.netClrColl, err = pdh.NewCollector[netClrValues](
		logger,
		pdh.CounterTypeRaw,
		".NET CLR Memory",
		[]string{"w3wp"},
	)
	if err != nil {
		logger.Warn("Failed to initialize .NET CLR collector", "err", err)
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
	return nil
}

func (c *GinWebAppCollector) Collect(ch chan<- prometheus.Metric) error {
	// 1. Collect ASP.NET Metrics (Traffic per path)
	if c.aspNetColl != nil {
		var aspNetData []aspNetValues
		if err := c.aspNetColl.Collect(&aspNetData); err == nil {
			for _, d := range aspNetData {
				// Filter for our target app if needed, or expose all
				// We assume "per path" means exposing all IIS Apps
				if strings.Contains(strings.ToLower(d.Name), "__total__") {
					continue
				}

				// Standardize the label to look like a path/app name
				labelName := normalizeAspNetInstanceName(d.Name)

				ch <- prometheus.MustNewConstMetric(
					prometheus.NewDesc(
						prometheus.BuildFQName("windows", "ginwebapp", "requests_sec"),
						"Requests per second",
						[]string{"app_path"}, nil,
					),
					prometheus.GaugeValue,
					d.RequestsSec,
					labelName,
				)
				ch <- prometheus.MustNewConstMetric(
					prometheus.NewDesc(
						prometheus.BuildFQName("windows", "ginwebapp", "requests_executing"),
						"Current executing requests",
						[]string{"app_path"}, nil,
					),
					prometheus.GaugeValue,
					d.RequestsExecuting,
					labelName,
				)
				ch <- prometheus.MustNewConstMetric(
					prometheus.NewDesc(
						prometheus.BuildFQName("windows", "ginwebapp", "requests_total"),
						"Total requests processed",
						[]string{"app_path"}, nil,
					),
					prometheus.CounterValue, // Counter for totals
					d.RequestsTotal,
					labelName,
				)
			}
		}
	}

	// 2. Collect Process Metrics (Resources)
	if c.processColl != nil {
		var processData []processValues
		if err := c.processColl.Collect(&processData); err == nil {
			for _, d := range processData {
				// d.Name will be w3wp, w3wp#1, etc.
				pid := formatPID(d.IDProcess)

				ch <- prometheus.MustNewConstMetric(
					prometheus.NewDesc(
						prometheus.BuildFQName("windows", "ginwebapp", "process_cpu_percent"),
						"Processor time percentage",
						[]string{"process", "pid"}, nil,
					),
					prometheus.GaugeValue,
					d.PercentProcessorTime,
					d.Name, pid,
				)
				ch <- prometheus.MustNewConstMetric(
					prometheus.NewDesc(
						prometheus.BuildFQName("windows", "ginwebapp", "process_memory_bytes"),
						"Working Set Private bytes",
						[]string{"process", "pid"}, nil,
					),
					prometheus.GaugeValue,
					d.WorkingSetPrivate,
					d.Name, pid,
				)
				ch <- prometheus.MustNewConstMetric(
					prometheus.NewDesc(
						prometheus.BuildFQName("windows", "ginwebapp", "process_io_bytes_sec"),
						"Total IO bytes per second",
						[]string{"process", "pid"}, nil,
					),
					prometheus.GaugeValue,
					d.IOReadBytesSec+d.IOWriteBytesSec,
					d.Name, pid,
				)
			}
		}
	}

	// 3. Collect .NET CLR Metrics
	if c.netClrColl != nil {
		var netClrData []netClrValues
		if err := c.netClrColl.Collect(&netClrData); err == nil {
			for _, d := range netClrData {
				// Ignore _Global_ instance
				if strings.Contains(d.Name, "_Global_") {
					continue
				}

				ch <- prometheus.MustNewConstMetric(
					prometheus.NewDesc(
						prometheus.BuildFQName("windows", "ginwebapp", "dotnet_gc_time_percent"),
						"Percentage of time in GC",
						[]string{"process"}, nil,
					),
					prometheus.GaugeValue,
					d.PercentTimeInGC,
					d.Name,
				)
				ch <- prometheus.MustNewConstMetric(
					prometheus.NewDesc(
						prometheus.BuildFQName("windows", "ginwebapp", "dotnet_heap_bytes"),
						"Bytes in all heaps",
						[]string{"process"}, nil,
					),
					prometheus.GaugeValue,
					d.BytesInAllHeaps,
					d.Name,
				)
			}
		}
	}

	return nil
}

func normalizeAspNetInstanceName(name string) string {
	// Instance names are like "_LM_W3SVC_1_ROOT_AppName"
	// We want to extract "AppName" or at least make it readable
	// _LM_W3SVC_1_ROOT is common prefix for Default Web Site (usually)
	name = strings.ReplaceAll(name, "_LM_W3SVC_1_ROOT_", "")
	name = strings.ReplaceAll(name, "_LM_W3SVC_", "site_")
	return name
}

func formatPID(f float64) string {
	return strconv.FormatUint(uint64(f), 10)
}
