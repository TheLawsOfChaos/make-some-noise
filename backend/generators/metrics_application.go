package generators

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"siem-event-generator/models"
)

// ApplicationMetricsGenerator generates application performance metrics for ITSI
type ApplicationMetricsGenerator struct {
	BaseGenerator
}

func init() {
	Register(&ApplicationMetricsGenerator{})
}

// GetEventType returns the event type for Application Metrics
func (g *ApplicationMetricsGenerator) GetEventType() models.EventType {
	return models.EventType{
		ID:          "metrics_application",
		Name:        "Application Performance Metrics",
		Category:    "metrics",
		Description: "Application metrics for ITSI: response time, request rate, error rate, queue depth, threads",
		EventIDs:    []string{"response_time", "request_rate", "error_rate", "queue", "threads", "connections", "jvm"},
	}
}

// GetTemplates returns available templates for Application Metrics
func (g *ApplicationMetricsGenerator) GetTemplates() []models.EventTemplate {
	return []models.EventTemplate{
		{
			ID:          "response_time",
			Name:        "Response Time Metrics",
			Category:    "metrics_application",
			EventID:     "response_time",
			Format:      "json",
			Description: "Application response time and latency percentiles",
			Sourcetype:  "metrics",
		},
		{
			ID:          "request_rate",
			Name:        "Request Rate Metrics",
			Category:    "metrics_application",
			EventID:     "request_rate",
			Format:      "json",
			Description: "Requests per second by endpoint and method",
			Sourcetype:  "metrics",
		},
		{
			ID:          "error_rate",
			Name:        "Error Rate Metrics",
			Category:    "metrics_application",
			EventID:     "error_rate",
			Format:      "json",
			Description: "Error counts and rates by type and endpoint",
			Sourcetype:  "metrics",
		},
		{
			ID:          "queue",
			Name:        "Queue Metrics",
			Category:    "metrics_application",
			EventID:     "queue",
			Format:      "json",
			Description: "Message queue depth, processing rates, and lag",
			Sourcetype:  "metrics",
		},
		{
			ID:          "threads",
			Name:        "Thread Pool Metrics",
			Category:    "metrics_application",
			EventID:     "threads",
			Format:      "json",
			Description: "Thread pool utilization and states",
			Sourcetype:  "metrics",
		},
		{
			ID:          "connections",
			Name:        "Connection Pool Metrics",
			Category:    "metrics_application",
			EventID:     "connections",
			Format:      "json",
			Description: "Connection pool usage for databases and external services",
			Sourcetype:  "metrics",
		},
		{
			ID:          "jvm",
			Name:        "JVM Metrics",
			Category:    "metrics_application",
			EventID:     "jvm",
			Format:      "json",
			Description: "JVM heap, GC, and class loading metrics",
			Sourcetype:  "metrics",
		},
	}
}

// Generate creates an Application Metrics event
func (g *ApplicationMetricsGenerator) Generate(templateID string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	switch templateID {
	case "response_time":
		return g.generateResponseTime(overrides)
	case "request_rate":
		return g.generateRequestRate(overrides)
	case "error_rate":
		return g.generateErrorRate(overrides)
	case "queue":
		return g.generateQueue(overrides)
	case "threads":
		return g.generateThreads(overrides)
	case "connections":
		return g.generateConnections(overrides)
	case "jvm":
		return g.generateJVM(overrides)
	default:
		return nil, fmt.Errorf("unknown template ID: %s", templateID)
	}
}

func (g *ApplicationMetricsGenerator) randomService() string {
	services := []string{"order-service", "payment-service", "user-service", "inventory-service", "notification-service", "auth-service", "catalog-service", "shipping-service"}
	return g.RandomChoice(services)
}

func (g *ApplicationMetricsGenerator) randomHost() string {
	return fmt.Sprintf("app-%02d.prod.internal", g.RandomInt(1, 20))
}

func (g *ApplicationMetricsGenerator) randomRegion() string {
	regions := []string{"us-east-1", "us-west-2", "us-gov-east-1", "us-gov-west-1"}
	return g.RandomChoice(regions)
}

func (g *ApplicationMetricsGenerator) randomEnvironment() string {
	envs := []string{"production", "staging", "development"}
	return g.RandomChoice(envs)
}

func (g *ApplicationMetricsGenerator) randomEndpoint() string {
	endpoints := []string{"/api/v1/orders", "/api/v1/users", "/api/v1/products", "/api/v1/cart", "/api/v1/checkout", "/api/v1/payments", "/api/v1/inventory", "/health", "/metrics"}
	return g.RandomChoice(endpoints)
}

func (g *ApplicationMetricsGenerator) randomMethod() string {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
	// Weight towards GET
	if g.RandomInt(0, 10) > 3 {
		return "GET"
	}
	return g.RandomChoice(methods)
}

// buildMetricEvent creates a Splunk HEC metrics format event
func (g *ApplicationMetricsGenerator) buildMetricEvent(metricName string, value float64, dimensions map[string]string, timestamp time.Time) map[string]interface{} {
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
		"source": "application_metrics",
		"host":   dimensions["host"],
		"fields": fields,
	}
}

func (g *ApplicationMetricsGenerator) generateResponseTime(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	service := g.randomService()
	host := g.randomHost()
	region := g.randomRegion()
	env := g.randomEnvironment()

	endpoints := []string{"/api/v1/orders", "/api/v1/users", "/api/v1/products", "/api/v1/cart", "/api/v1/checkout"}
	metrics := make([]map[string]interface{}, 0)

	for _, endpoint := range endpoints {
		for _, method := range []string{"GET", "POST"} {
			// Generate realistic latency distribution
			baseLatency := float64(g.RandomInt(5, 50))
			if endpoint == "/api/v1/checkout" {
				baseLatency = float64(g.RandomInt(100, 500)) // Checkout is slower
			}

			p50 := baseLatency + float64(g.RandomInt(0, 20))
			p75 := p50 * 1.5
			p90 := p50 * 2.5
			p95 := p50 * 4
			p99 := p50 * 8
			max := p50 * 15
			min := baseLatency * 0.5
			avg := (p50 + p90) / 2

			dimensions := map[string]string{
				"host":        host,
				"region":      region,
				"environment": env,
				"service":     service,
				"endpoint":    endpoint,
				"method":      method,
			}

			metrics = append(metrics,
				g.buildMetricEvent("app.response_time.p50", p50, dimensions, timestamp),
				g.buildMetricEvent("app.response_time.p75", p75, dimensions, timestamp),
				g.buildMetricEvent("app.response_time.p90", p90, dimensions, timestamp),
				g.buildMetricEvent("app.response_time.p95", p95, dimensions, timestamp),
				g.buildMetricEvent("app.response_time.p99", p99, dimensions, timestamp),
				g.buildMetricEvent("app.response_time.max", max, dimensions, timestamp),
				g.buildMetricEvent("app.response_time.min", min, dimensions, timestamp),
				g.buildMetricEvent("app.response_time.avg", avg, dimensions, timestamp),
			)
		}
	}

	fields := map[string]interface{}{
		"metrics":     metrics,
		"host":        host,
		"region":      region,
		"environment": env,
		"service":     service,
	}

	fields = g.ApplyOverrides(fields, overrides)
	rawEvent, _ := json.MarshalIndent(metrics, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "metrics_application",
		EventID:    "response_time",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "metrics",
	}, nil
}

func (g *ApplicationMetricsGenerator) generateRequestRate(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	service := g.randomService()
	host := g.randomHost()
	region := g.randomRegion()
	env := g.randomEnvironment()

	endpoints := []string{"/api/v1/orders", "/api/v1/users", "/api/v1/products", "/api/v1/cart", "/api/v1/checkout", "/health"}
	methods := []string{"GET", "POST", "PUT", "DELETE"}
	metrics := make([]map[string]interface{}, 0)

	totalRequests := 0.0
	for _, endpoint := range endpoints {
		for _, method := range methods {
			// Health checks are frequent
			var rps float64
			if endpoint == "/health" && method == "GET" {
				rps = float64(g.RandomInt(10, 100))
			} else if method == "GET" {
				rps = float64(g.RandomInt(50, 1000))
			} else if method == "POST" {
				rps = float64(g.RandomInt(10, 200))
			} else {
				rps = float64(g.RandomInt(1, 50))
			}

			totalRequests += rps

			dimensions := map[string]string{
				"host":        host,
				"region":      region,
				"environment": env,
				"service":     service,
				"endpoint":    endpoint,
				"method":      method,
			}

			metrics = append(metrics,
				g.buildMetricEvent("app.requests.rate", rps, dimensions, timestamp),
				g.buildMetricEvent("app.requests.count", rps*60, dimensions, timestamp), // per minute
			)
		}
	}

	// Total service metrics
	serviceDimensions := map[string]string{
		"host":        host,
		"region":      region,
		"environment": env,
		"service":     service,
	}
	metrics = append(metrics,
		g.buildMetricEvent("app.requests.total_rate", totalRequests, serviceDimensions, timestamp),
		g.buildMetricEvent("app.requests.total_count", totalRequests*60, serviceDimensions, timestamp),
	)

	fields := map[string]interface{}{
		"metrics":     metrics,
		"host":        host,
		"region":      region,
		"environment": env,
		"service":     service,
	}

	fields = g.ApplyOverrides(fields, overrides)
	rawEvent, _ := json.MarshalIndent(metrics, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "metrics_application",
		EventID:    "request_rate",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "metrics",
	}, nil
}

func (g *ApplicationMetricsGenerator) generateErrorRate(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	service := g.randomService()
	host := g.randomHost()
	region := g.randomRegion()
	env := g.randomEnvironment()

	errorTypes := []struct {
		code        string
		description string
	}{
		{"400", "bad_request"},
		{"401", "unauthorized"},
		{"403", "forbidden"},
		{"404", "not_found"},
		{"429", "rate_limited"},
		{"500", "internal_error"},
		{"502", "bad_gateway"},
		{"503", "service_unavailable"},
		{"504", "gateway_timeout"},
	}

	endpoints := []string{"/api/v1/orders", "/api/v1/users", "/api/v1/products", "/api/v1/checkout"}
	metrics := make([]map[string]interface{}, 0)

	totalErrors := 0.0
	total5xx := 0.0
	total4xx := 0.0

	for _, endpoint := range endpoints {
		for _, errType := range errorTypes {
			// Most errors should be rare
			var errorCount float64
			switch errType.code {
			case "404":
				errorCount = float64(g.RandomInt(0, 50))
			case "400":
				errorCount = float64(g.RandomInt(0, 30))
			case "401", "403":
				errorCount = float64(g.RandomInt(0, 20))
			case "429":
				errorCount = float64(g.RandomInt(0, 10))
			case "500":
				errorCount = float64(g.RandomInt(0, 5))
			default:
				errorCount = float64(g.RandomInt(0, 3))
			}

			totalErrors += errorCount
			if errType.code[0] == '5' {
				total5xx += errorCount
			} else {
				total4xx += errorCount
			}

			dimensions := map[string]string{
				"host":        host,
				"region":      region,
				"environment": env,
				"service":     service,
				"endpoint":    endpoint,
				"status_code": errType.code,
				"error_type":  errType.description,
			}

			metrics = append(metrics,
				g.buildMetricEvent("app.errors.count", errorCount, dimensions, timestamp),
			)
		}
	}

	// Aggregated error metrics
	serviceDimensions := map[string]string{
		"host":        host,
		"region":      region,
		"environment": env,
		"service":     service,
	}

	totalRequests := float64(g.RandomInt(10000, 100000))
	errorRate := (totalErrors / totalRequests) * 100

	metrics = append(metrics,
		g.buildMetricEvent("app.errors.total", totalErrors, serviceDimensions, timestamp),
		g.buildMetricEvent("app.errors.4xx", total4xx, serviceDimensions, timestamp),
		g.buildMetricEvent("app.errors.5xx", total5xx, serviceDimensions, timestamp),
		g.buildMetricEvent("app.errors.rate_percent", errorRate, serviceDimensions, timestamp),
	)

	fields := map[string]interface{}{
		"metrics":     metrics,
		"host":        host,
		"region":      region,
		"environment": env,
		"service":     service,
	}

	fields = g.ApplyOverrides(fields, overrides)
	rawEvent, _ := json.MarshalIndent(metrics, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "metrics_application",
		EventID:    "error_rate",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "metrics",
	}, nil
}

func (g *ApplicationMetricsGenerator) generateQueue(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	service := g.randomService()
	host := g.randomHost()
	region := g.randomRegion()
	env := g.randomEnvironment()

	queues := []struct {
		name      string
		queueType string
	}{
		{"orders-pending", "kafka"},
		{"notifications-outbound", "kafka"},
		{"payment-processing", "rabbitmq"},
		{"email-queue", "sqs"},
		{"async-tasks", "redis"},
		{"dead-letter", "kafka"},
	}

	metrics := make([]map[string]interface{}, 0)

	for _, queue := range queues {
		depth := float64(g.RandomInt(0, 10000))
		if queue.name == "dead-letter" {
			depth = float64(g.RandomInt(0, 100)) // DLQ should be small
		}

		messagesIn := float64(g.RandomInt(100, 5000))
		messagesOut := float64(g.RandomInt(100, 5000))
		consumerLag := float64(g.RandomInt(0, 1000))
		oldestMessageAge := float64(g.RandomInt(0, 300)) // seconds

		dimensions := map[string]string{
			"host":        host,
			"region":      region,
			"environment": env,
			"service":     service,
			"queue":       queue.name,
			"queue_type":  queue.queueType,
		}

		metrics = append(metrics,
			g.buildMetricEvent("queue.depth", depth, dimensions, timestamp),
			g.buildMetricEvent("queue.messages_in", messagesIn, dimensions, timestamp),
			g.buildMetricEvent("queue.messages_out", messagesOut, dimensions, timestamp),
			g.buildMetricEvent("queue.consumer_lag", consumerLag, dimensions, timestamp),
			g.buildMetricEvent("queue.oldest_message_age_seconds", oldestMessageAge, dimensions, timestamp),
			g.buildMetricEvent("queue.consumers", float64(g.RandomInt(1, 10)), dimensions, timestamp),
		)
	}

	fields := map[string]interface{}{
		"metrics":     metrics,
		"host":        host,
		"region":      region,
		"environment": env,
		"service":     service,
	}

	fields = g.ApplyOverrides(fields, overrides)
	rawEvent, _ := json.MarshalIndent(metrics, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "metrics_application",
		EventID:    "queue",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "metrics",
	}, nil
}

func (g *ApplicationMetricsGenerator) generateThreads(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	service := g.randomService()
	host := g.randomHost()
	region := g.randomRegion()
	env := g.randomEnvironment()

	pools := []struct {
		name    string
		maxSize int
	}{
		{"http-worker", 200},
		{"async-executor", 50},
		{"scheduled-tasks", 20},
		{"database-pool", 30},
		{"io-worker", 100},
	}

	metrics := make([]map[string]interface{}, 0)

	for _, pool := range pools {
		maxSize := float64(pool.maxSize)
		activePercent := float64(g.RandomInt(10, 80))
		active := maxSize * activePercent / 100
		idle := maxSize - active
		queued := float64(g.RandomInt(0, 50))

		dimensions := map[string]string{
			"host":        host,
			"region":      region,
			"environment": env,
			"service":     service,
			"pool":        pool.name,
		}

		metrics = append(metrics,
			g.buildMetricEvent("threads.max", maxSize, dimensions, timestamp),
			g.buildMetricEvent("threads.active", active, dimensions, timestamp),
			g.buildMetricEvent("threads.idle", idle, dimensions, timestamp),
			g.buildMetricEvent("threads.queued", queued, dimensions, timestamp),
			g.buildMetricEvent("threads.utilization_percent", activePercent, dimensions, timestamp),
		)
	}

	// Overall thread metrics
	serviceDimensions := map[string]string{
		"host":        host,
		"region":      region,
		"environment": env,
		"service":     service,
	}

	metrics = append(metrics,
		g.buildMetricEvent("threads.total", float64(g.RandomInt(100, 500)), serviceDimensions, timestamp),
		g.buildMetricEvent("threads.daemon", float64(g.RandomInt(20, 100)), serviceDimensions, timestamp),
		g.buildMetricEvent("threads.peak", float64(g.RandomInt(150, 600)), serviceDimensions, timestamp),
		g.buildMetricEvent("threads.started_total", float64(g.RandomInt(1000, 100000)), serviceDimensions, timestamp),
	)

	fields := map[string]interface{}{
		"metrics":     metrics,
		"host":        host,
		"region":      region,
		"environment": env,
		"service":     service,
	}

	fields = g.ApplyOverrides(fields, overrides)
	rawEvent, _ := json.MarshalIndent(metrics, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "metrics_application",
		EventID:    "threads",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "metrics",
	}, nil
}

func (g *ApplicationMetricsGenerator) generateConnections(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	service := g.randomService()
	host := g.randomHost()
	region := g.randomRegion()
	env := g.randomEnvironment()

	connectionPools := []struct {
		name       string
		target     string
		targetType string
		maxSize    int
	}{
		{"postgres-primary", "db-primary.internal:5432", "database", 50},
		{"postgres-replica", "db-replica.internal:5432", "database", 30},
		{"redis-cache", "redis.internal:6379", "cache", 100},
		{"elasticsearch", "es.internal:9200", "search", 20},
		{"kafka", "kafka.internal:9092", "messaging", 10},
		{"http-external", "api.external.com:443", "http", 50},
	}

	metrics := make([]map[string]interface{}, 0)

	for _, pool := range connectionPools {
		maxSize := float64(pool.maxSize)
		activePercent := float64(g.RandomInt(20, 90))
		active := maxSize * activePercent / 100
		idle := maxSize - active
		pending := float64(g.RandomInt(0, 10))
		created := float64(g.RandomInt(100, 10000))
		destroyed := float64(g.RandomInt(50, 5000))
		timeouts := float64(g.RandomInt(0, 10))

		dimensions := map[string]string{
			"host":        host,
			"region":      region,
			"environment": env,
			"service":     service,
			"pool":        pool.name,
			"target":      pool.target,
			"target_type": pool.targetType,
		}

		metrics = append(metrics,
			g.buildMetricEvent("connections.max", maxSize, dimensions, timestamp),
			g.buildMetricEvent("connections.active", active, dimensions, timestamp),
			g.buildMetricEvent("connections.idle", idle, dimensions, timestamp),
			g.buildMetricEvent("connections.pending", pending, dimensions, timestamp),
			g.buildMetricEvent("connections.created_total", created, dimensions, timestamp),
			g.buildMetricEvent("connections.destroyed_total", destroyed, dimensions, timestamp),
			g.buildMetricEvent("connections.timeouts_total", timeouts, dimensions, timestamp),
			g.buildMetricEvent("connections.utilization_percent", activePercent, dimensions, timestamp),
			g.buildMetricEvent("connections.wait_time_ms", float64(g.RandomInt(0, 100)), dimensions, timestamp),
		)
	}

	fields := map[string]interface{}{
		"metrics":     metrics,
		"host":        host,
		"region":      region,
		"environment": env,
		"service":     service,
	}

	fields = g.ApplyOverrides(fields, overrides)
	rawEvent, _ := json.MarshalIndent(metrics, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "metrics_application",
		EventID:    "connections",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "metrics",
	}, nil
}

func (g *ApplicationMetricsGenerator) generateJVM(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	service := g.randomService()
	host := g.randomHost()
	region := g.randomRegion()
	env := g.randomEnvironment()

	// JVM heap settings
	heapMax := float64(g.RandomChoice([]string{"2", "4", "8", "16"})[0]-'0') * 1024 * 1024 * 1024
	if heapMax == 0 {
		heapMax = 4 * 1024 * 1024 * 1024
	}
	heapUsedPercent := float64(g.RandomInt(40, 85))
	heapUsed := heapMax * heapUsedPercent / 100
	heapCommitted := heapMax * float64(g.RandomInt(70, 100)) / 100

	dimensions := map[string]string{
		"host":        host,
		"region":      region,
		"environment": env,
		"service":     service,
	}

	metrics := []map[string]interface{}{
		// Heap memory
		g.buildMetricEvent("jvm.memory.heap.max", heapMax, dimensions, timestamp),
		g.buildMetricEvent("jvm.memory.heap.used", heapUsed, dimensions, timestamp),
		g.buildMetricEvent("jvm.memory.heap.committed", heapCommitted, dimensions, timestamp),
		g.buildMetricEvent("jvm.memory.heap.percent", heapUsedPercent, dimensions, timestamp),

		// Non-heap memory
		g.buildMetricEvent("jvm.memory.nonheap.used", float64(g.RandomInt(50, 300))*1024*1024, dimensions, timestamp),
		g.buildMetricEvent("jvm.memory.nonheap.committed", float64(g.RandomInt(100, 500))*1024*1024, dimensions, timestamp),
	}

	// Memory pool metrics
	pools := []struct {
		name string
		max  float64
	}{
		{"eden", heapMax * 0.3},
		{"survivor", heapMax * 0.1},
		{"old_gen", heapMax * 0.6},
		{"metaspace", 256 * 1024 * 1024},
		{"code_cache", 128 * 1024 * 1024},
	}

	for _, pool := range pools {
		usedPercent := float64(g.RandomInt(20, 90))
		poolDimensions := map[string]string{
			"host":        host,
			"region":      region,
			"environment": env,
			"service":     service,
			"pool":        pool.name,
		}
		metrics = append(metrics,
			g.buildMetricEvent("jvm.memory.pool.used", pool.max*usedPercent/100, poolDimensions, timestamp),
			g.buildMetricEvent("jvm.memory.pool.max", pool.max, poolDimensions, timestamp),
			g.buildMetricEvent("jvm.memory.pool.percent", usedPercent, poolDimensions, timestamp),
		)
	}

	// GC metrics
	gcTypes := []string{"young", "old"}
	for _, gcType := range gcTypes {
		gcDimensions := map[string]string{
			"host":        host,
			"region":      region,
			"environment": env,
			"service":     service,
			"gc":          gcType,
		}

		var count, timeMs float64
		if gcType == "young" {
			count = float64(g.RandomInt(100, 10000))
			timeMs = float64(g.RandomInt(1000, 50000))
		} else {
			count = float64(g.RandomInt(1, 100))
			timeMs = float64(g.RandomInt(100, 10000))
		}

		metrics = append(metrics,
			g.buildMetricEvent("jvm.gc.count", count, gcDimensions, timestamp),
			g.buildMetricEvent("jvm.gc.time_ms", timeMs, gcDimensions, timestamp),
		)
	}

	// Class loading
	metrics = append(metrics,
		g.buildMetricEvent("jvm.classes.loaded", float64(g.RandomInt(10000, 50000)), dimensions, timestamp),
		g.buildMetricEvent("jvm.classes.unloaded", float64(g.RandomInt(0, 1000)), dimensions, timestamp),
	)

	// Buffer pools
	bufferPools := []string{"direct", "mapped"}
	for _, bp := range bufferPools {
		bpDimensions := map[string]string{
			"host":        host,
			"region":      region,
			"environment": env,
			"service":     service,
			"buffer_pool": bp,
		}
		metrics = append(metrics,
			g.buildMetricEvent("jvm.buffer.count", float64(g.RandomInt(10, 100)), bpDimensions, timestamp),
			g.buildMetricEvent("jvm.buffer.used", float64(g.RandomInt(1, 100))*1024*1024, bpDimensions, timestamp),
			g.buildMetricEvent("jvm.buffer.capacity", float64(g.RandomInt(10, 200))*1024*1024, bpDimensions, timestamp),
		)
	}

	fields := map[string]interface{}{
		"metrics":     metrics,
		"host":        host,
		"region":      region,
		"environment": env,
		"service":     service,
	}

	fields = g.ApplyOverrides(fields, overrides)
	rawEvent, _ := json.MarshalIndent(metrics, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "metrics_application",
		EventID:    "jvm",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "metrics",
	}, nil
}
