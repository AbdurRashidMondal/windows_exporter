package collector

import (
	"strconv"

	"log/slog"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus-community/windows_exporter/internal/mi"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/shirou/gopsutil/v3/process"
)

const GinProcessName = "ginprocess"

type GinProcessCollector struct {
	cpuPercent *prometheus.GaugeVec
	memoryMB   *prometheus.GaugeVec
}

func NewGinProcess() *GinProcessCollector {
	return &GinProcessCollector{}
}

func NewGinProcessWithFlags(_ *kingpin.Application) *GinProcessCollector {
	return &GinProcessCollector{}
}

func (c *GinProcessCollector) GetName() string {
	return GinProcessName
}

func (c *GinProcessCollector) Build(logger *slog.Logger, _ *mi.Session) error {
	c.cpuPercent = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "windows",
			Subsystem: "ginprocess",
			Name:      "cpu_percent",
			Help:      "CPU utilization percent per process",
		},
		[]string{"pid", "name", "username", "cmdline", "status"},
	)

	c.memoryMB = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "windows",
			Subsystem: "ginprocess",
			Name:      "memory_mb",
			Help:      "Memory usage in MB per process",
		},
		[]string{"pid", "name", "username", "cmdline", "status"},
	)

	return nil
}

func (c *GinProcessCollector) Close() error {
	// No cleanup required
	return nil
}

func (c *GinProcessCollector) Collect(ch chan<- prometheus.Metric) error {
	c.cpuPercent.Reset()
	c.memoryMB.Reset()

	procs, err := process.Processes()
	if err != nil {
		return err
	}

	for _, p := range procs {
		pid := strconv.Itoa(int(p.Pid))

		// Get process name
		name, _ := p.Name()

		// Get username (may fail for system processes)
		username, err := p.Username()
		if err != nil {
			username = "unknown"
		}

		// Get command line - keeping full cmdline for process identification
		cmdline, err := p.Cmdline()
		if err != nil {
			cmdline = ""
		}

		// Get process status
		status, err := p.Status()
		if err != nil {
			status = []string{"unknown"}
		}
		statusStr := ""
		if len(status) > 0 {
			statusStr = status[0]
		}

		// Collect CPU metric
		if cpu, err := p.CPUPercent(); err == nil {
			c.cpuPercent.WithLabelValues(pid, name, username, cmdline, statusStr).Set(cpu)
		}

		// Collect Memory metric
		if mem, err := p.MemoryInfo(); err == nil {
			c.memoryMB.WithLabelValues(pid, name, username, cmdline, statusStr).
				Set(float64(mem.RSS) / 1024 / 1024)
		}
	}

	c.cpuPercent.Collect(ch)
	c.memoryMB.Collect(ch)

	return nil
}
