package generators

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"siem-event-generator/models"
)

// SystemMetricsGenerator generates system infrastructure metrics for ITSI
type SystemMetricsGenerator struct {
	BaseGenerator
}

func init() {
	Register(&SystemMetricsGenerator{})
}

// GetEventType returns the event type for System Metrics
func (g *SystemMetricsGenerator) GetEventType() models.EventType {
	return models.EventType{
		ID:          "metrics_system",
		Name:        "System Infrastructure Metrics",
		Category:    "metrics",
		Description: "Infrastructure metrics for ITSI: CPU, memory, disk, network, temperature, load average",
		EventIDs:    []string{"cpu", "memory", "disk_space", "disk_io", "network", "load", "temperature"},
	}
}

// GetTemplates returns available templates for System Metrics
func (g *SystemMetricsGenerator) GetTemplates() []models.EventTemplate {
	return []models.EventTemplate{
		{
			ID:          "cpu",
			Name:        "CPU Metrics",
			Category:    "metrics_system",
			EventID:     "cpu",
			Format:      "json",
			Description: "CPU utilization metrics per core and total",
			Sourcetype:  "metrics",
		},
		{
			ID:          "memory",
			Name:        "Memory Metrics",
			Category:    "metrics_system",
			EventID:     "memory",
			Format:      "json",
			Description: "Memory usage metrics (used, free, cached, buffers)",
			Sourcetype:  "metrics",
		},
		{
			ID:          "disk_space",
			Name:        "Disk Space Metrics",
			Category:    "metrics_system",
			EventID:     "disk_space",
			Format:      "json",
			Description: "Disk space utilization by mount point",
			Sourcetype:  "metrics",
		},
		{
			ID:          "disk_io",
			Name:        "Disk I/O Metrics",
			Category:    "metrics_system",
			EventID:     "disk_io",
			Format:      "json",
			Description: "Disk read/write throughput and IOPS",
			Sourcetype:  "metrics",
		},
		{
			ID:          "network",
			Name:        "Network Metrics",
			Category:    "metrics_system",
			EventID:     "network",
			Format:      "json",
			Description: "Network interface throughput and errors",
			Sourcetype:  "metrics",
		},
		{
			ID:          "load",
			Name:        "System Load Metrics",
			Category:    "metrics_system",
			EventID:     "load",
			Format:      "json",
			Description: "System load average and process counts",
			Sourcetype:  "metrics",
		},
		{
			ID:          "temperature",
			Name:        "Temperature Metrics",
			Category:    "metrics_system",
			EventID:     "temperature",
			Format:      "json",
			Description: "Hardware temperature sensors (CPU, GPU, chassis)",
			Sourcetype:  "metrics",
		},
	}
}

// Generate creates a System Metrics event
func (g *SystemMetricsGenerator) Generate(templateID string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	switch templateID {
	case "cpu":
		return g.generateCPU(overrides)
	case "memory":
		return g.generateMemory(overrides)
	case "disk_space":
		return g.generateDiskSpace(overrides)
	case "disk_io":
		return g.generateDiskIO(overrides)
	case "network":
		return g.generateNetwork(overrides)
	case "load":
		return g.generateLoad(overrides)
	case "temperature":
		return g.generateTemperature(overrides)
	default:
		return nil, fmt.Errorf("unknown template ID: %s", templateID)
	}
}

func (g *SystemMetricsGenerator) randomHost() string {
	prefixes := []string{"web", "app", "db", "cache", "api", "worker", "proxy", "monitor"}
	return fmt.Sprintf("%s-%02d.prod.internal", g.RandomChoice(prefixes), g.RandomInt(1, 20))
}

func (g *SystemMetricsGenerator) randomRegion() string {
	regions := []string{"us-east-1", "us-west-2", "us-gov-east-1", "us-gov-west-1"}
	return g.RandomChoice(regions)
}

func (g *SystemMetricsGenerator) randomEnvironment() string {
	envs := []string{"production", "staging", "development"}
	return g.RandomChoice(envs)
}

func (g *SystemMetricsGenerator) randomDatacenter() string {
	dcs := []string{"dc1", "dc2", "dc3", "aws-east", "aws-west", "gcp-central"}
	return g.RandomChoice(dcs)
}

// buildMetricEvent creates a Splunk HEC metrics format event
func (g *SystemMetricsGenerator) buildMetricEvent(metricName string, value float64, dimensions map[string]string, timestamp time.Time) map[string]interface{} {
	fields := map[string]interface{}{
		"metric_name": metricName,
		"_value":      value,
	}
	for k, v := range dimensions {
		fields[k] = v
	}

	return map[string]interface{}{
		"time":   timestamp.Unix(),
		"event":  "metric",
		"source": "infrastructure_metrics",
		"host":   dimensions["host"],
		"fields": fields,
	}
}

func (g *SystemMetricsGenerator) generateCPU(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	host := g.randomHost()
	region := g.randomRegion()
	env := g.randomEnvironment()

	// Generate metrics for multiple CPU cores
	numCores := g.RandomInt(4, 32)
	metrics := make([]map[string]interface{}, 0)

	totalUsage := 0.0
	for i := 0; i < numCores; i++ {
		// Simulate realistic CPU patterns - some cores busier than others
		baseUsage := float64(g.RandomInt(5, 40))
		if g.RandomInt(0, 10) > 7 { // 30% chance of high usage
			baseUsage = float64(g.RandomInt(60, 95))
		}

		coreMetric := g.buildMetricEvent(
			"cpu.percent",
			baseUsage,
			map[string]string{
				"host":        host,
				"region":      region,
				"environment": env,
				"cpu":         fmt.Sprintf("cpu%d", i),
			},
			timestamp,
		)
		metrics = append(metrics, coreMetric)
		totalUsage += baseUsage
	}

	// Add total CPU metric
	totalMetric := g.buildMetricEvent(
		"cpu.percent.total",
		totalUsage/float64(numCores),
		map[string]string{
			"host":        host,
			"region":      region,
			"environment": env,
		},
		timestamp,
	)
	metrics = append(metrics, totalMetric)

	// Add system/user/idle breakdown
	userPct := float64(g.RandomInt(10, 60))
	sysPct := float64(g.RandomInt(5, 25))
	idlePct := 100 - userPct - sysPct
	iowaitPct := float64(g.RandomInt(0, 10))

	for metricName, value := range map[string]float64{
		"cpu.user":   userPct,
		"cpu.system": sysPct,
		"cpu.idle":   idlePct,
		"cpu.iowait": iowaitPct,
	} {
		m := g.buildMetricEvent(metricName, value, map[string]string{
			"host":        host,
			"region":      region,
			"environment": env,
		}, timestamp)
		metrics = append(metrics, m)
	}

	fields := map[string]interface{}{
		"metrics":     metrics,
		"host":        host,
		"region":      region,
		"environment": env,
		"num_cores":   numCores,
	}

	fields = g.ApplyOverrides(fields, overrides)
	rawEvent, _ := json.MarshalIndent(metrics, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "metrics_system",
		EventID:    "cpu",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "metrics",
	}, nil
}

func (g *SystemMetricsGenerator) generateMemory(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	host := g.randomHost()
	region := g.randomRegion()
	env := g.randomEnvironment()

	// Total memory in GB (8GB to 256GB)
	totalGB := float64(g.RandomChoice([]string{"8", "16", "32", "64", "128", "256"})[0]-'0') * 8
	if totalGB == 0 {
		totalGB = 16
	}

	totalBytes := totalGB * 1024 * 1024 * 1024
	usedPercent := float64(g.RandomInt(30, 85))
	usedBytes := totalBytes * usedPercent / 100
	freeBytes := totalBytes - usedBytes
	cachedBytes := totalBytes * float64(g.RandomInt(10, 30)) / 100
	buffersBytes := totalBytes * float64(g.RandomInt(2, 8)) / 100

	dimensions := map[string]string{
		"host":        host,
		"region":      region,
		"environment": env,
	}

	metrics := []map[string]interface{}{
		g.buildMetricEvent("memory.total", totalBytes, dimensions, timestamp),
		g.buildMetricEvent("memory.used", usedBytes, dimensions, timestamp),
		g.buildMetricEvent("memory.free", freeBytes, dimensions, timestamp),
		g.buildMetricEvent("memory.cached", cachedBytes, dimensions, timestamp),
		g.buildMetricEvent("memory.buffers", buffersBytes, dimensions, timestamp),
		g.buildMetricEvent("memory.percent", usedPercent, dimensions, timestamp),
		g.buildMetricEvent("memory.available", freeBytes+cachedBytes+buffersBytes, dimensions, timestamp),
	}

	// Swap metrics
	swapTotal := totalBytes / 2
	swapUsedPercent := float64(g.RandomInt(0, 30))
	swapUsed := swapTotal * swapUsedPercent / 100

	metrics = append(metrics,
		g.buildMetricEvent("swap.total", swapTotal, dimensions, timestamp),
		g.buildMetricEvent("swap.used", swapUsed, dimensions, timestamp),
		g.buildMetricEvent("swap.percent", swapUsedPercent, dimensions, timestamp),
	)

	fields := map[string]interface{}{
		"metrics":     metrics,
		"host":        host,
		"region":      region,
		"environment": env,
	}

	fields = g.ApplyOverrides(fields, overrides)
	rawEvent, _ := json.MarshalIndent(metrics, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "metrics_system",
		EventID:    "memory",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "metrics",
	}, nil
}

func (g *SystemMetricsGenerator) generateDiskSpace(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	host := g.randomHost()
	region := g.randomRegion()
	env := g.randomEnvironment()

	mountPoints := []struct {
		path    string
		sizeGB  int
		purpose string
	}{
		{"/", 100, "root"},
		{"/var", 200, "var"},
		{"/var/log", 50, "logs"},
		{"/data", 1000, "data"},
		{"/tmp", 20, "temp"},
		{"/home", 100, "home"},
	}

	metrics := make([]map[string]interface{}, 0)

	for _, mp := range mountPoints {
		totalBytes := float64(mp.sizeGB) * 1024 * 1024 * 1024
		usedPercent := float64(g.RandomInt(20, 90))
		// Data volumes tend to be fuller
		if mp.purpose == "data" || mp.purpose == "logs" {
			usedPercent = float64(g.RandomInt(50, 95))
		}
		usedBytes := totalBytes * usedPercent / 100
		freeBytes := totalBytes - usedBytes
		inodesTotal := float64(g.RandomInt(1000000, 10000000))
		inodesUsedPercent := float64(g.RandomInt(5, 40))
		inodesUsed := inodesTotal * inodesUsedPercent / 100

		dimensions := map[string]string{
			"host":        host,
			"region":      region,
			"environment": env,
			"mount":       mp.path,
			"purpose":     mp.purpose,
		}

		metrics = append(metrics,
			g.buildMetricEvent("disk.total", totalBytes, dimensions, timestamp),
			g.buildMetricEvent("disk.used", usedBytes, dimensions, timestamp),
			g.buildMetricEvent("disk.free", freeBytes, dimensions, timestamp),
			g.buildMetricEvent("disk.percent", usedPercent, dimensions, timestamp),
			g.buildMetricEvent("disk.inodes.total", inodesTotal, dimensions, timestamp),
			g.buildMetricEvent("disk.inodes.used", inodesUsed, dimensions, timestamp),
			g.buildMetricEvent("disk.inodes.percent", inodesUsedPercent, dimensions, timestamp),
		)
	}

	fields := map[string]interface{}{
		"metrics":     metrics,
		"host":        host,
		"region":      region,
		"environment": env,
	}

	fields = g.ApplyOverrides(fields, overrides)
	rawEvent, _ := json.MarshalIndent(metrics, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "metrics_system",
		EventID:    "disk_space",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "metrics",
	}, nil
}

func (g *SystemMetricsGenerator) generateDiskIO(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	host := g.randomHost()
	region := g.randomRegion()
	env := g.randomEnvironment()

	devices := []string{"sda", "sdb", "nvme0n1", "nvme1n1"}
	metrics := make([]map[string]interface{}, 0)

	for _, device := range devices {
		// Simulate disk I/O patterns
		readBytesPerSec := float64(g.RandomInt(1000000, 500000000))  // 1MB to 500MB/s
		writeBytesPerSec := float64(g.RandomInt(1000000, 300000000)) // 1MB to 300MB/s
		readIOPS := float64(g.RandomInt(100, 50000))
		writeIOPS := float64(g.RandomInt(100, 30000))
		avgQueueLen := float64(g.RandomInt(0, 20)) + float64(g.RandomInt(0, 99))/100
		utilization := float64(g.RandomInt(5, 95))
		avgReadLatencyMs := float64(g.RandomInt(1, 50)) + float64(g.RandomInt(0, 99))/100
		avgWriteLatencyMs := float64(g.RandomInt(1, 100)) + float64(g.RandomInt(0, 99))/100

		dimensions := map[string]string{
			"host":        host,
			"region":      region,
			"environment": env,
			"device":      device,
		}

		metrics = append(metrics,
			g.buildMetricEvent("diskio.read_bytes", readBytesPerSec, dimensions, timestamp),
			g.buildMetricEvent("diskio.write_bytes", writeBytesPerSec, dimensions, timestamp),
			g.buildMetricEvent("diskio.read_iops", readIOPS, dimensions, timestamp),
			g.buildMetricEvent("diskio.write_iops", writeIOPS, dimensions, timestamp),
			g.buildMetricEvent("diskio.queue_length", avgQueueLen, dimensions, timestamp),
			g.buildMetricEvent("diskio.utilization", utilization, dimensions, timestamp),
			g.buildMetricEvent("diskio.read_latency_ms", avgReadLatencyMs, dimensions, timestamp),
			g.buildMetricEvent("diskio.write_latency_ms", avgWriteLatencyMs, dimensions, timestamp),
		)
	}

	fields := map[string]interface{}{
		"metrics":     metrics,
		"host":        host,
		"region":      region,
		"environment": env,
	}

	fields = g.ApplyOverrides(fields, overrides)
	rawEvent, _ := json.MarshalIndent(metrics, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "metrics_system",
		EventID:    "disk_io",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "metrics",
	}, nil
}

func (g *SystemMetricsGenerator) generateNetwork(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	host := g.randomHost()
	region := g.randomRegion()
	env := g.randomEnvironment()

	interfaces := []string{"eth0", "eth1", "ens192", "bond0"}
	metrics := make([]map[string]interface{}, 0)

	for _, iface := range interfaces {
		rxBytesPerSec := float64(g.RandomInt(100000, 1000000000)) // 100KB to 1GB/s
		txBytesPerSec := float64(g.RandomInt(100000, 500000000))  // 100KB to 500MB/s
		rxPacketsPerSec := float64(g.RandomInt(1000, 1000000))
		txPacketsPerSec := float64(g.RandomInt(1000, 500000))
		rxErrors := float64(g.RandomInt(0, 10))
		txErrors := float64(g.RandomInt(0, 5))
		rxDropped := float64(g.RandomInt(0, 100))
		txDropped := float64(g.RandomInt(0, 50))

		dimensions := map[string]string{
			"host":        host,
			"region":      region,
			"environment": env,
			"interface":   iface,
		}

		metrics = append(metrics,
			g.buildMetricEvent("net.bytes_recv", rxBytesPerSec, dimensions, timestamp),
			g.buildMetricEvent("net.bytes_sent", txBytesPerSec, dimensions, timestamp),
			g.buildMetricEvent("net.packets_recv", rxPacketsPerSec, dimensions, timestamp),
			g.buildMetricEvent("net.packets_sent", txPacketsPerSec, dimensions, timestamp),
			g.buildMetricEvent("net.errors_recv", rxErrors, dimensions, timestamp),
			g.buildMetricEvent("net.errors_sent", txErrors, dimensions, timestamp),
			g.buildMetricEvent("net.dropped_recv", rxDropped, dimensions, timestamp),
			g.buildMetricEvent("net.dropped_sent", txDropped, dimensions, timestamp),
		)
	}

	// TCP connection metrics
	tcpDimensions := map[string]string{
		"host":        host,
		"region":      region,
		"environment": env,
	}
	metrics = append(metrics,
		g.buildMetricEvent("net.tcp.established", float64(g.RandomInt(100, 5000)), tcpDimensions, timestamp),
		g.buildMetricEvent("net.tcp.time_wait", float64(g.RandomInt(10, 500)), tcpDimensions, timestamp),
		g.buildMetricEvent("net.tcp.close_wait", float64(g.RandomInt(0, 50)), tcpDimensions, timestamp),
		g.buildMetricEvent("net.tcp.listen", float64(g.RandomInt(10, 100)), tcpDimensions, timestamp),
	)

	fields := map[string]interface{}{
		"metrics":     metrics,
		"host":        host,
		"region":      region,
		"environment": env,
	}

	fields = g.ApplyOverrides(fields, overrides)
	rawEvent, _ := json.MarshalIndent(metrics, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "metrics_system",
		EventID:    "network",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "metrics",
	}, nil
}

func (g *SystemMetricsGenerator) generateLoad(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	host := g.randomHost()
	region := g.randomRegion()
	env := g.randomEnvironment()

	numCores := g.RandomInt(4, 32)
	// Load averages relative to number of cores
	load1 := float64(numCores) * (float64(g.RandomInt(10, 150)) / 100)
	load5 := float64(numCores) * (float64(g.RandomInt(10, 120)) / 100)
	load15 := float64(numCores) * (float64(g.RandomInt(10, 100)) / 100)

	dimensions := map[string]string{
		"host":        host,
		"region":      region,
		"environment": env,
	}

	metrics := []map[string]interface{}{
		g.buildMetricEvent("system.load1", load1, dimensions, timestamp),
		g.buildMetricEvent("system.load5", load5, dimensions, timestamp),
		g.buildMetricEvent("system.load15", load15, dimensions, timestamp),
		g.buildMetricEvent("system.cpu_count", float64(numCores), dimensions, timestamp),
		g.buildMetricEvent("system.processes.total", float64(g.RandomInt(100, 500)), dimensions, timestamp),
		g.buildMetricEvent("system.processes.running", float64(g.RandomInt(1, 20)), dimensions, timestamp),
		g.buildMetricEvent("system.processes.sleeping", float64(g.RandomInt(80, 400)), dimensions, timestamp),
		g.buildMetricEvent("system.processes.zombie", float64(g.RandomInt(0, 3)), dimensions, timestamp),
		g.buildMetricEvent("system.uptime_seconds", float64(g.RandomInt(3600, 31536000)), dimensions, timestamp),
		g.buildMetricEvent("system.context_switches", float64(g.RandomInt(10000, 1000000)), dimensions, timestamp),
		g.buildMetricEvent("system.interrupts", float64(g.RandomInt(5000, 500000)), dimensions, timestamp),
	}

	fields := map[string]interface{}{
		"metrics":     metrics,
		"host":        host,
		"region":      region,
		"environment": env,
		"num_cores":   numCores,
	}

	fields = g.ApplyOverrides(fields, overrides)
	rawEvent, _ := json.MarshalIndent(metrics, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "metrics_system",
		EventID:    "load",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "metrics",
	}, nil
}

func (g *SystemMetricsGenerator) generateTemperature(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	host := g.randomHost()
	region := g.randomRegion()
	env := g.randomEnvironment()
	dc := g.randomDatacenter()

	metrics := make([]map[string]interface{}, 0)

	// CPU temperature per core
	numCores := g.RandomInt(4, 16)
	for i := 0; i < numCores; i++ {
		temp := float64(g.RandomInt(35, 75)) + float64(g.RandomInt(0, 99))/100
		dimensions := map[string]string{
			"host":        host,
			"region":      region,
			"environment": env,
			"datacenter":  dc,
			"sensor":      "cpu",
			"core":        fmt.Sprintf("%d", i),
		}
		metrics = append(metrics, g.buildMetricEvent("temperature.celsius", temp, dimensions, timestamp))
	}

	// CPU package temperature
	cpuPkgTemp := float64(g.RandomInt(40, 80)) + float64(g.RandomInt(0, 99))/100
	metrics = append(metrics, g.buildMetricEvent("temperature.celsius", cpuPkgTemp, map[string]string{
		"host":        host,
		"region":      region,
		"environment": env,
		"datacenter":  dc,
		"sensor":      "cpu_package",
	}, timestamp))

	// GPU temperature (if present)
	if g.RandomInt(0, 10) > 3 { // 70% have GPU
		gpuTemp := float64(g.RandomInt(45, 85)) + float64(g.RandomInt(0, 99))/100
		metrics = append(metrics, g.buildMetricEvent("temperature.celsius", gpuTemp, map[string]string{
			"host":        host,
			"region":      region,
			"environment": env,
			"datacenter":  dc,
			"sensor":      "gpu",
			"gpu":         "0",
		}, timestamp))
	}

	// Chassis/ambient temperature
	chassisTemp := float64(g.RandomInt(20, 35)) + float64(g.RandomInt(0, 99))/100
	metrics = append(metrics, g.buildMetricEvent("temperature.celsius", chassisTemp, map[string]string{
		"host":        host,
		"region":      region,
		"environment": env,
		"datacenter":  dc,
		"sensor":      "chassis",
	}, timestamp))

	// Disk temperature
	diskTemp := float64(g.RandomInt(30, 50)) + float64(g.RandomInt(0, 99))/100
	metrics = append(metrics, g.buildMetricEvent("temperature.celsius", diskTemp, map[string]string{
		"host":        host,
		"region":      region,
		"environment": env,
		"datacenter":  dc,
		"sensor":      "disk",
		"device":      "sda",
	}, timestamp))

	// Fan speeds (RPM)
	for i := 0; i < g.RandomInt(2, 6); i++ {
		fanRPM := float64(g.RandomInt(800, 3500))
		metrics = append(metrics, g.buildMetricEvent("fan.rpm", fanRPM, map[string]string{
			"host":        host,
			"region":      region,
			"environment": env,
			"datacenter":  dc,
			"fan":         fmt.Sprintf("fan%d", i),
		}, timestamp))
	}

	fields := map[string]interface{}{
		"metrics":     metrics,
		"host":        host,
		"region":      region,
		"environment": env,
		"datacenter":  dc,
	}

	fields = g.ApplyOverrides(fields, overrides)
	rawEvent, _ := json.MarshalIndent(metrics, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "metrics_system",
		EventID:    "temperature",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "metrics",
	}, nil
}
