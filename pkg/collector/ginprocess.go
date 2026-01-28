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
		[]string{"pid", "name"},
	)

	c.memoryMB = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "windows",
			Subsystem: "ginprocess",
			Name:      "memory_mb",
			Help:      "Memory usage in MB per process",
		},
		[]string{"pid", "name"},
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
		name, _ := p.Name()

		if cpu, err := p.CPUPercent(); err == nil {
			c.cpuPercent.WithLabelValues(pid, name).Set(cpu)
		}

		if mem, err := p.MemoryInfo(); err == nil {
			c.memoryMB.WithLabelValues(pid, name).
				Set(float64(mem.RSS) / 1024 / 1024)
		}
	}

	c.cpuPercent.Collect(ch)
	c.memoryMB.Collect(ch)

	return nil
}
