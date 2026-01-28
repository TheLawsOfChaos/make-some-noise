package generators

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"siem-event-generator/models"
)

// WebAPIMetricsGenerator generates web/API performance metrics for ITSI
type WebAPIMetricsGenerator struct {
	BaseGenerator
}

func init() {
	Register(&WebAPIMetricsGenerator{})
}

// GetEventType returns the event type for Web/API Metrics
func (g *WebAPIMetricsGenerator) GetEventType() models.EventType {
	return models.EventType{
		ID:          "metrics_webapi",
		Name:        "Web/API Metrics",
		Category:    "metrics",
		Description: "Web and API metrics for ITSI: HTTP codes, requests/sec, latency percentiles, bandwidth",
		EventIDs:    []string{"http_status", "latency", "throughput", "bandwidth", "ssl", "upstream", "cache"},
	}
}

// GetTemplates returns available templates for Web/API Metrics
func (g *WebAPIMetricsGenerator) GetTemplates() []models.EventTemplate {
	return []models.EventTemplate{
		{
			ID:          "http_status",
			Name:        "HTTP Status Code Metrics",
			Category:    "metrics_webapi",
			EventID:     "http_status",
			Format:      "json",
			Description: "HTTP response code distribution and rates",
			Sourcetype:  "metrics",
		},
		{
			ID:          "latency",
			Name:        "Latency Percentile Metrics",
			Category:    "metrics_webapi",
			EventID:     "latency",
			Format:      "json",
			Description: "Request latency percentiles (p50, p90, p95, p99)",
			Sourcetype:  "metrics",
		},
		{
			ID:          "throughput",
			Name:        "Throughput Metrics",
			Category:    "metrics_webapi",
			EventID:     "throughput",
			Format:      "json",
			Description: "Requests per second by endpoint and method",
			Sourcetype:  "metrics",
		},
		{
			ID:          "bandwidth",
			Name:        "Bandwidth Metrics",
			Category:    "metrics_webapi",
			EventID:     "bandwidth",
			Format:      "json",
			Description: "Data transfer rates and sizes",
			Sourcetype:  "metrics",
		},
		{
			ID:          "ssl",
			Name:        "SSL/TLS Metrics",
			Category:    "metrics_webapi",
			EventID:     "ssl",
			Format:      "json",
			Description: "SSL handshake times and certificate metrics",
			Sourcetype:  "metrics",
		},
		{
			ID:          "upstream",
			Name:        "Upstream/Backend Metrics",
			Category:    "metrics_webapi",
			EventID:     "upstream",
			Format:      "json",
			Description: "Backend server health and response times",
			Sourcetype:  "metrics",
		},
		{
			ID:          "cache",
			Name:        "Cache Metrics",
			Category:    "metrics_webapi",
			EventID:     "cache",
			Format:      "json",
			Description: "Cache hit ratios and effectiveness",
			Sourcetype:  "metrics",
		},
	}
}

// Generate creates a Web/API Metrics event
func (g *WebAPIMetricsGenerator) Generate(templateID string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	switch templateID {
	case "http_status":
		return g.generateHTTPStatus(overrides)
	case "latency":
		return g.generateLatency(overrides)
	case "throughput":
		return g.generateThroughput(overrides)
	case "bandwidth":
		return g.generateBandwidth(overrides)
	case "ssl":
		return g.generateSSL(overrides)
	case "upstream":
		return g.generateUpstream(overrides)
	case "cache":
		return g.generateCache(overrides)
	default:
		return nil, fmt.Errorf("unknown template ID: %s", templateID)
	}
}

func (g *WebAPIMetricsGenerator) randomHost() string {
	prefixes := []string{"web", "api", "gateway", "edge", "lb", "cdn"}
	return fmt.Sprintf("%s-%02d.prod.internal", g.RandomChoice(prefixes), g.RandomInt(1, 10))
}

func (g *WebAPIMetricsGenerator) randomVirtualHost() string {
	vhosts := []string{"api.example.com", "www.example.com", "app.example.com", "mobile-api.example.com", "admin.example.com"}
	return g.RandomChoice(vhosts)
}

func (g *WebAPIMetricsGenerator) randomEndpoint() string {
	endpoints := []string{
		"/api/v1/users",
		"/api/v1/orders",
		"/api/v1/products",
		"/api/v1/cart",
		"/api/v1/checkout",
		"/api/v1/search",
		"/api/v1/auth/login",
		"/api/v1/auth/logout",
		"/api/v2/graphql",
		"/health",
		"/metrics",
	}
	return g.RandomChoice(endpoints)
}

func (g *WebAPIMetricsGenerator) randomRegion() string {
	regions := []string{"us-east-1", "us-west-2", "us-gov-east-1", "us-gov-west-1"}
	return g.RandomChoice(regions)
}

func (g *WebAPIMetricsGenerator) randomEnvironment() string {
	envs := []string{"production", "staging", "development"}
	return g.RandomChoice(envs)
}

// buildMetricEvent creates a Splunk HEC metrics format event
func (g *WebAPIMetricsGenerator) buildMetricEvent(metricName string, value float64, dimensions map[string]string, timestamp time.Time) map[string]interface{} {
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
		"source": "webapi_metrics",
		"host":   dimensions["host"],
		"fields": fields,
	}
}

func (g *WebAPIMetricsGenerator) generateHTTPStatus(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	host := g.randomHost()
	vhost := g.randomVirtualHost()
	region := g.randomRegion()
	env := g.randomEnvironment()

	// HTTP status code distribution
	statusCodes := []struct {
		code   string
		class  string
		weight int
	}{
		{"200", "2xx", 8000},
		{"201", "2xx", 500},
		{"204", "2xx", 300},
		{"301", "3xx", 100},
		{"302", "3xx", 150},
		{"304", "3xx", 500},
		{"400", "4xx", 200},
		{"401", "4xx", 100},
		{"403", "4xx", 50},
		{"404", "4xx", 300},
		{"429", "4xx", 50},
		{"500", "5xx", 20},
		{"502", "5xx", 10},
		{"503", "5xx", 5},
		{"504", "5xx", 5},
	}

	metrics := make([]map[string]interface{}, 0)

	total2xx := 0.0
	total3xx := 0.0
	total4xx := 0.0
	total5xx := 0.0
	totalRequests := 0.0

	for _, sc := range statusCodes {
		count := float64(g.RandomInt(0, sc.weight*2))
		totalRequests += count

		switch sc.class {
		case "2xx":
			total2xx += count
		case "3xx":
			total3xx += count
		case "4xx":
			total4xx += count
		case "5xx":
			total5xx += count
		}

		dimensions := map[string]string{
			"host":         host,
			"vhost":        vhost,
			"region":       region,
			"environment":  env,
			"status_code":  sc.code,
			"status_class": sc.class,
		}

		metrics = append(metrics,
			g.buildMetricEvent("http.responses.count", count, dimensions, timestamp),
			g.buildMetricEvent("http.responses.rate", count/60, dimensions, timestamp),
		)
	}

	// Aggregated metrics
	aggDimensions := map[string]string{
		"host":        host,
		"vhost":       vhost,
		"region":      region,
		"environment": env,
	}

	metrics = append(metrics,
		g.buildMetricEvent("http.responses.total", totalRequests, aggDimensions, timestamp),
		g.buildMetricEvent("http.responses.2xx", total2xx, aggDimensions, timestamp),
		g.buildMetricEvent("http.responses.3xx", total3xx, aggDimensions, timestamp),
		g.buildMetricEvent("http.responses.4xx", total4xx, aggDimensions, timestamp),
		g.buildMetricEvent("http.responses.5xx", total5xx, aggDimensions, timestamp),
		g.buildMetricEvent("http.responses.success_rate", (total2xx+total3xx)/totalRequests*100, aggDimensions, timestamp),
		g.buildMetricEvent("http.responses.error_rate", (total4xx+total5xx)/totalRequests*100, aggDimensions, timestamp),
	)

	fields := map[string]interface{}{
		"metrics":     metrics,
		"host":        host,
		"vhost":       vhost,
		"region":      region,
		"environment": env,
	}

	fields = g.ApplyOverrides(fields, overrides)
	rawEvent, _ := json.MarshalIndent(metrics, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "metrics_webapi",
		EventID:    "http_status",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "metrics",
	}, nil
}

func (g *WebAPIMetricsGenerator) generateLatency(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	host := g.randomHost()
	vhost := g.randomVirtualHost()
	region := g.randomRegion()
	env := g.randomEnvironment()

	endpoints := []string{"/api/v1/users", "/api/v1/orders", "/api/v1/products", "/api/v1/search", "/api/v1/checkout"}
	methods := []string{"GET", "POST"}
	metrics := make([]map[string]interface{}, 0)

	for _, endpoint := range endpoints {
		for _, method := range methods {
			// Base latency varies by endpoint
			var baseLatency float64
			switch endpoint {
			case "/api/v1/search":
				baseLatency = float64(g.RandomInt(50, 200))
			case "/api/v1/checkout":
				baseLatency = float64(g.RandomInt(100, 500))
			default:
				baseLatency = float64(g.RandomInt(10, 50))
			}

			p50 := baseLatency + float64(g.RandomInt(0, 20))
			p75 := p50 * 1.3
			p90 := p50 * 2.0
			p95 := p50 * 3.0
			p99 := p50 * 5.0
			p999 := p50 * 10.0
			max := p50 * 20.0
			min := baseLatency * 0.3
			avg := (p50 + p90) / 2
			stddev := (p99 - p50) / 2

			dimensions := map[string]string{
				"host":        host,
				"vhost":       vhost,
				"region":      region,
				"environment": env,
				"endpoint":    endpoint,
				"method":      method,
			}

			metrics = append(metrics,
				g.buildMetricEvent("http.latency.p50_ms", p50, dimensions, timestamp),
				g.buildMetricEvent("http.latency.p75_ms", p75, dimensions, timestamp),
				g.buildMetricEvent("http.latency.p90_ms", p90, dimensions, timestamp),
				g.buildMetricEvent("http.latency.p95_ms", p95, dimensions, timestamp),
				g.buildMetricEvent("http.latency.p99_ms", p99, dimensions, timestamp),
				g.buildMetricEvent("http.latency.p999_ms", p999, dimensions, timestamp),
				g.buildMetricEvent("http.latency.max_ms", max, dimensions, timestamp),
				g.buildMetricEvent("http.latency.min_ms", min, dimensions, timestamp),
				g.buildMetricEvent("http.latency.avg_ms", avg, dimensions, timestamp),
				g.buildMetricEvent("http.latency.stddev_ms", stddev, dimensions, timestamp),
			)
		}
	}

	// Overall latency
	overallDimensions := map[string]string{
		"host":        host,
		"vhost":       vhost,
		"region":      region,
		"environment": env,
	}

	overallP50 := float64(g.RandomInt(20, 80))
	metrics = append(metrics,
		g.buildMetricEvent("http.latency.overall.p50_ms", overallP50, overallDimensions, timestamp),
		g.buildMetricEvent("http.latency.overall.p90_ms", overallP50*2.5, overallDimensions, timestamp),
		g.buildMetricEvent("http.latency.overall.p99_ms", overallP50*5, overallDimensions, timestamp),
	)

	fields := map[string]interface{}{
		"metrics":     metrics,
		"host":        host,
		"vhost":       vhost,
		"region":      region,
		"environment": env,
	}

	fields = g.ApplyOverrides(fields, overrides)
	rawEvent, _ := json.MarshalIndent(metrics, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "metrics_webapi",
		EventID:    "latency",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "metrics",
	}, nil
}

func (g *WebAPIMetricsGenerator) generateThroughput(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	host := g.randomHost()
	vhost := g.randomVirtualHost()
	region := g.randomRegion()
	env := g.randomEnvironment()

	endpoints := []string{"/api/v1/users", "/api/v1/orders", "/api/v1/products", "/api/v1/search", "/api/v1/auth/login", "/health"}
	methods := []string{"GET", "POST", "PUT", "DELETE"}
	metrics := make([]map[string]interface{}, 0)

	totalRPS := 0.0
	for _, endpoint := range endpoints {
		for _, method := range methods {
			var rps float64
			// Weight by typical traffic patterns
			if endpoint == "/health" && method == "GET" {
				rps = float64(g.RandomInt(10, 50))
			} else if method == "GET" {
				rps = float64(g.RandomInt(100, 2000))
			} else if method == "POST" {
				rps = float64(g.RandomInt(50, 500))
			} else {
				rps = float64(g.RandomInt(10, 100))
			}

			totalRPS += rps

			dimensions := map[string]string{
				"host":        host,
				"vhost":       vhost,
				"region":      region,
				"environment": env,
				"endpoint":    endpoint,
				"method":      method,
			}

			metrics = append(metrics,
				g.buildMetricEvent("http.requests.rate", rps, dimensions, timestamp),
				g.buildMetricEvent("http.requests.count", rps*60, dimensions, timestamp),
			)
		}
	}

	// Total throughput
	totalDimensions := map[string]string{
		"host":        host,
		"vhost":       vhost,
		"region":      region,
		"environment": env,
	}

	metrics = append(metrics,
		g.buildMetricEvent("http.requests.total_rate", totalRPS, totalDimensions, timestamp),
		g.buildMetricEvent("http.requests.total_count", totalRPS*60, totalDimensions, timestamp),
		g.buildMetricEvent("http.requests.peak_rate", totalRPS*float64(g.RandomInt(110, 150))/100, totalDimensions, timestamp),
	)

	// Active connections
	metrics = append(metrics,
		g.buildMetricEvent("http.connections.active", float64(g.RandomInt(100, 5000)), totalDimensions, timestamp),
		g.buildMetricEvent("http.connections.reading", float64(g.RandomInt(10, 500)), totalDimensions, timestamp),
		g.buildMetricEvent("http.connections.writing", float64(g.RandomInt(10, 500)), totalDimensions, timestamp),
		g.buildMetricEvent("http.connections.waiting", float64(g.RandomInt(50, 2000)), totalDimensions, timestamp),
	)

	fields := map[string]interface{}{
		"metrics":     metrics,
		"host":        host,
		"vhost":       vhost,
		"region":      region,
		"environment": env,
	}

	fields = g.ApplyOverrides(fields, overrides)
	rawEvent, _ := json.MarshalIndent(metrics, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "metrics_webapi",
		EventID:    "throughput",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "metrics",
	}, nil
}

func (g *WebAPIMetricsGenerator) generateBandwidth(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	host := g.randomHost()
	vhost := g.randomVirtualHost()
	region := g.randomRegion()
	env := g.randomEnvironment()

	dimensions := map[string]string{
		"host":        host,
		"vhost":       vhost,
		"region":      region,
		"environment": env,
	}

	// Bandwidth metrics
	bytesIn := float64(g.RandomInt(10000000, 1000000000))  // 10MB to 1GB per interval
	bytesOut := float64(g.RandomInt(50000000, 5000000000)) // 50MB to 5GB per interval

	metrics := []map[string]interface{}{
		g.buildMetricEvent("http.bytes.in", bytesIn, dimensions, timestamp),
		g.buildMetricEvent("http.bytes.out", bytesOut, dimensions, timestamp),
		g.buildMetricEvent("http.bytes.total", bytesIn+bytesOut, dimensions, timestamp),

		// Rate (bytes per second)
		g.buildMetricEvent("http.bandwidth.in_bps", bytesIn/60*8, dimensions, timestamp),
		g.buildMetricEvent("http.bandwidth.out_bps", bytesOut/60*8, dimensions, timestamp),

		// Request/response sizes
		g.buildMetricEvent("http.request.avg_size_bytes", float64(g.RandomInt(500, 5000)), dimensions, timestamp),
		g.buildMetricEvent("http.response.avg_size_bytes", float64(g.RandomInt(1000, 50000)), dimensions, timestamp),
		g.buildMetricEvent("http.request.max_size_bytes", float64(g.RandomInt(10000, 10000000)), dimensions, timestamp),
		g.buildMetricEvent("http.response.max_size_bytes", float64(g.RandomInt(100000, 100000000)), dimensions, timestamp),
	}

	// Per-content-type metrics
	contentTypes := []struct {
		ctype  string
		weight int
	}{
		{"application/json", 60},
		{"text/html", 15},
		{"image/png", 10},
		{"image/jpeg", 8},
		{"application/javascript", 5},
		{"text/css", 2},
	}

	for _, ct := range contentTypes {
		ctDimensions := map[string]string{
			"host":         host,
			"vhost":        vhost,
			"region":       region,
			"environment":  env,
			"content_type": ct.ctype,
		}
		ctBytes := bytesOut * float64(ct.weight) / 100
		metrics = append(metrics,
			g.buildMetricEvent("http.bytes.by_content_type", ctBytes, ctDimensions, timestamp),
		)
	}

	// Compression metrics
	metrics = append(metrics,
		g.buildMetricEvent("http.compression.ratio", float64(g.RandomInt(20, 80))/100, dimensions, timestamp),
		g.buildMetricEvent("http.compression.saved_bytes", bytesOut*float64(g.RandomInt(20, 60))/100, dimensions, timestamp),
	)

	fields := map[string]interface{}{
		"metrics":     metrics,
		"host":        host,
		"vhost":       vhost,
		"region":      region,
		"environment": env,
	}

	fields = g.ApplyOverrides(fields, overrides)
	rawEvent, _ := json.MarshalIndent(metrics, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "metrics_webapi",
		EventID:    "bandwidth",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "metrics",
	}, nil
}

func (g *WebAPIMetricsGenerator) generateSSL(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	host := g.randomHost()
	vhost := g.randomVirtualHost()
	region := g.randomRegion()
	env := g.randomEnvironment()

	dimensions := map[string]string{
		"host":        host,
		"vhost":       vhost,
		"region":      region,
		"environment": env,
	}

	// SSL handshake metrics
	metrics := []map[string]interface{}{
		g.buildMetricEvent("ssl.handshake.time_ms", float64(g.RandomInt(5, 100)), dimensions, timestamp),
		g.buildMetricEvent("ssl.handshake.count", float64(g.RandomInt(1000, 100000)), dimensions, timestamp),
		g.buildMetricEvent("ssl.handshake.failures", float64(g.RandomInt(0, 50)), dimensions, timestamp),
		g.buildMetricEvent("ssl.handshake.resumptions", float64(g.RandomInt(500, 50000)), dimensions, timestamp),
		g.buildMetricEvent("ssl.handshake.resumption_rate", float64(g.RandomInt(40, 80)), dimensions, timestamp),
	}

	// SSL version distribution
	versions := []struct {
		version string
		weight  int
	}{
		{"TLSv1.3", 70},
		{"TLSv1.2", 29},
		{"TLSv1.1", 1},
	}

	for _, v := range versions {
		vDimensions := map[string]string{
			"host":        host,
			"vhost":       vhost,
			"region":      region,
			"environment": env,
			"ssl_version": v.version,
		}
		metrics = append(metrics,
			g.buildMetricEvent("ssl.connections.by_version", float64(g.RandomInt(0, v.weight*100)), vDimensions, timestamp),
		)
	}

	// Cipher suite distribution
	ciphers := []string{"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256", "ECDHE-RSA-AES256-GCM-SHA384"}
	for _, cipher := range ciphers {
		cDimensions := map[string]string{
			"host":        host,
			"vhost":       vhost,
			"region":      region,
			"environment": env,
			"cipher":      cipher,
		}
		metrics = append(metrics,
			g.buildMetricEvent("ssl.connections.by_cipher", float64(g.RandomInt(100, 10000)), cDimensions, timestamp),
		)
	}

	// Certificate metrics
	daysUntilExpiry := g.RandomInt(30, 365)
	metrics = append(metrics,
		g.buildMetricEvent("ssl.certificate.days_until_expiry", float64(daysUntilExpiry), dimensions, timestamp),
		g.buildMetricEvent("ssl.certificate.is_valid", 1, dimensions, timestamp),
	)

	fields := map[string]interface{}{
		"metrics":     metrics,
		"host":        host,
		"vhost":       vhost,
		"region":      region,
		"environment": env,
	}

	fields = g.ApplyOverrides(fields, overrides)
	rawEvent, _ := json.MarshalIndent(metrics, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "metrics_webapi",
		EventID:    "ssl",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "metrics",
	}, nil
}

func (g *WebAPIMetricsGenerator) generateUpstream(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	host := g.randomHost()
	vhost := g.randomVirtualHost()
	region := g.randomRegion()
	env := g.randomEnvironment()

	upstreams := []struct {
		name    string
		servers int
	}{
		{"api-backend", 5},
		{"auth-service", 3},
		{"search-cluster", 4},
		{"static-content", 2},
	}

	metrics := make([]map[string]interface{}, 0)

	for _, upstream := range upstreams {
		upstreamDimensions := map[string]string{
			"host":        host,
			"vhost":       vhost,
			"region":      region,
			"environment": env,
			"upstream":    upstream.name,
		}

		// Upstream-level metrics
		metrics = append(metrics,
			g.buildMetricEvent("upstream.requests.rate", float64(g.RandomInt(100, 5000)), upstreamDimensions, timestamp),
			g.buildMetricEvent("upstream.response_time.avg_ms", float64(g.RandomInt(10, 100)), upstreamDimensions, timestamp),
			g.buildMetricEvent("upstream.active_connections", float64(g.RandomInt(10, 500)), upstreamDimensions, timestamp),
		)

		// Per-server metrics
		for i := 1; i <= upstream.servers; i++ {
			serverDimensions := map[string]string{
				"host":        host,
				"vhost":       vhost,
				"region":      region,
				"environment": env,
				"upstream":    upstream.name,
				"server":      fmt.Sprintf("%s-%02d", upstream.name, i),
				"server_addr": fmt.Sprintf("10.0.%d.%d:8080", g.RandomInt(1, 10), i),
			}

			// Health state (1 = healthy, 0 = unhealthy)
			healthState := 1.0
			if g.RandomInt(0, 100) > 95 { // 5% chance unhealthy
				healthState = 0
			}

			weight := float64(g.RandomInt(1, 10))

			metrics = append(metrics,
				g.buildMetricEvent("upstream.server.health", healthState, serverDimensions, timestamp),
				g.buildMetricEvent("upstream.server.weight", weight, serverDimensions, timestamp),
				g.buildMetricEvent("upstream.server.active", float64(g.RandomInt(5, 100)), serverDimensions, timestamp),
				g.buildMetricEvent("upstream.server.requests", float64(g.RandomInt(1000, 100000)), serverDimensions, timestamp),
				g.buildMetricEvent("upstream.server.response_time_ms", float64(g.RandomInt(5, 150)), serverDimensions, timestamp),
				g.buildMetricEvent("upstream.server.fails", float64(g.RandomInt(0, 10)), serverDimensions, timestamp),
				g.buildMetricEvent("upstream.server.unavailable", float64(g.RandomInt(0, 5)), serverDimensions, timestamp),
			)
		}
	}

	fields := map[string]interface{}{
		"metrics":     metrics,
		"host":        host,
		"vhost":       vhost,
		"region":      region,
		"environment": env,
	}

	fields = g.ApplyOverrides(fields, overrides)
	rawEvent, _ := json.MarshalIndent(metrics, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "metrics_webapi",
		EventID:    "upstream",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "metrics",
	}, nil
}

func (g *WebAPIMetricsGenerator) generateCache(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	host := g.randomHost()
	vhost := g.randomVirtualHost()
	region := g.randomRegion()
	env := g.randomEnvironment()

	dimensions := map[string]string{
		"host":        host,
		"vhost":       vhost,
		"region":      region,
		"environment": env,
	}

	// Cache hit ratio (typically high for CDN/reverse proxy)
	hitRatio := float64(g.RandomInt(70, 98)) + float64(g.RandomInt(0, 99))/100

	totalRequests := float64(g.RandomInt(10000, 1000000))
	hits := totalRequests * hitRatio / 100
	misses := totalRequests - hits
	stale := float64(g.RandomInt(0, int(totalRequests/100)))
	bypass := float64(g.RandomInt(0, int(totalRequests/50)))
	expired := float64(g.RandomInt(0, int(totalRequests/20)))

	metrics := []map[string]interface{}{
		// Hit/miss metrics
		g.buildMetricEvent("cache.hit_ratio", hitRatio, dimensions, timestamp),
		g.buildMetricEvent("cache.hits", hits, dimensions, timestamp),
		g.buildMetricEvent("cache.misses", misses, dimensions, timestamp),
		g.buildMetricEvent("cache.stale", stale, dimensions, timestamp),
		g.buildMetricEvent("cache.bypass", bypass, dimensions, timestamp),
		g.buildMetricEvent("cache.expired", expired, dimensions, timestamp),
		g.buildMetricEvent("cache.revalidated", float64(g.RandomInt(0, int(totalRequests/10))), dimensions, timestamp),

		// Size metrics
		g.buildMetricEvent("cache.size_bytes", float64(g.RandomInt(1000000000, 100000000000)), dimensions, timestamp),
		g.buildMetricEvent("cache.items", float64(g.RandomInt(10000, 1000000)), dimensions, timestamp),
		g.buildMetricEvent("cache.evictions", float64(g.RandomInt(0, 10000)), dimensions, timestamp),

		// Bandwidth saved
		g.buildMetricEvent("cache.bytes_saved", float64(g.RandomInt(1000000000, 10000000000)), dimensions, timestamp),
	}

	// Cache status distribution
	cacheStatuses := []struct {
		status string
		count  float64
	}{
		{"HIT", hits},
		{"MISS", misses},
		{"STALE", stale},
		{"BYPASS", bypass},
		{"EXPIRED", expired},
	}

	for _, cs := range cacheStatuses {
		csDimensions := map[string]string{
			"host":         host,
			"vhost":        vhost,
			"region":       region,
			"environment":  env,
			"cache_status": cs.status,
		}
		metrics = append(metrics,
			g.buildMetricEvent("cache.requests.by_status", cs.count, csDimensions, timestamp),
		)
	}

	// Cache zones
	zones := []string{"static_assets", "api_responses", "html_pages", "images"}
	for _, zone := range zones {
		zoneDimensions := map[string]string{
			"host":        host,
			"vhost":       vhost,
			"region":      region,
			"environment": env,
			"zone":        zone,
		}
		zoneHitRatio := float64(g.RandomInt(60, 99))
		metrics = append(metrics,
			g.buildMetricEvent("cache.zone.hit_ratio", zoneHitRatio, zoneDimensions, timestamp),
			g.buildMetricEvent("cache.zone.size_bytes", float64(g.RandomInt(100000000, 10000000000)), zoneDimensions, timestamp),
			g.buildMetricEvent("cache.zone.items", float64(g.RandomInt(1000, 100000)), zoneDimensions, timestamp),
		)
	}

	fields := map[string]interface{}{
		"metrics":     metrics,
		"host":        host,
		"vhost":       vhost,
		"region":      region,
		"environment": env,
	}

	fields = g.ApplyOverrides(fields, overrides)
	rawEvent, _ := json.MarshalIndent(metrics, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "metrics_webapi",
		EventID:    "cache",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "metrics",
	}, nil
}
