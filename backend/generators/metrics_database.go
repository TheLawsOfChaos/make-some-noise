package generators

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"siem-event-generator/models"
)

// DatabaseMetricsGenerator generates database performance metrics for ITSI
type DatabaseMetricsGenerator struct {
	BaseGenerator
}

func init() {
	Register(&DatabaseMetricsGenerator{})
}

// GetEventType returns the event type for Database Metrics
func (g *DatabaseMetricsGenerator) GetEventType() models.EventType {
	return models.EventType{
		ID:          "metrics_database",
		Name:        "Database Metrics",
		Category:    "metrics",
		Description: "Database metrics for ITSI: query latency, connections, buffer pool, TPS, replication lag",
		EventIDs:    []string{"query_performance", "connections", "buffer_pool", "transactions", "replication", "locks", "tablespace"},
	}
}

// GetTemplates returns available templates for Database Metrics
func (g *DatabaseMetricsGenerator) GetTemplates() []models.EventTemplate {
	return []models.EventTemplate{
		{
			ID:          "query_performance",
			Name:        "Query Performance Metrics",
			Category:    "metrics_database",
			EventID:     "query_performance",
			Format:      "json",
			Description: "Query latency, throughput, and slow query counts",
			Sourcetype:  "metrics",
		},
		{
			ID:          "connections",
			Name:        "Database Connection Metrics",
			Category:    "metrics_database",
			EventID:     "connections",
			Format:      "json",
			Description: "Connection pool utilization and states",
			Sourcetype:  "metrics",
		},
		{
			ID:          "buffer_pool",
			Name:        "Buffer Pool Metrics",
			Category:    "metrics_database",
			EventID:     "buffer_pool",
			Format:      "json",
			Description: "Buffer/cache hit ratios and memory usage",
			Sourcetype:  "metrics",
		},
		{
			ID:          "transactions",
			Name:        "Transaction Metrics",
			Category:    "metrics_database",
			EventID:     "transactions",
			Format:      "json",
			Description: "Transactions per second, commits, rollbacks",
			Sourcetype:  "metrics",
		},
		{
			ID:          "replication",
			Name:        "Replication Metrics",
			Category:    "metrics_database",
			EventID:     "replication",
			Format:      "json",
			Description: "Replication lag, sync status, and throughput",
			Sourcetype:  "metrics",
		},
		{
			ID:          "locks",
			Name:        "Lock Metrics",
			Category:    "metrics_database",
			EventID:     "locks",
			Format:      "json",
			Description: "Lock waits, deadlocks, and contention",
			Sourcetype:  "metrics",
		},
		{
			ID:          "tablespace",
			Name:        "Tablespace Metrics",
			Category:    "metrics_database",
			EventID:     "tablespace",
			Format:      "json",
			Description: "Tablespace and disk usage",
			Sourcetype:  "metrics",
		},
	}
}

// Generate creates a Database Metrics event
func (g *DatabaseMetricsGenerator) Generate(templateID string, overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	switch templateID {
	case "query_performance":
		return g.generateQueryPerformance(overrides)
	case "connections":
		return g.generateConnections(overrides)
	case "buffer_pool":
		return g.generateBufferPool(overrides)
	case "transactions":
		return g.generateTransactions(overrides)
	case "replication":
		return g.generateReplication(overrides)
	case "locks":
		return g.generateLocks(overrides)
	case "tablespace":
		return g.generateTablespace(overrides)
	default:
		return nil, fmt.Errorf("unknown template ID: %s", templateID)
	}
}

func (g *DatabaseMetricsGenerator) randomHost() string {
	prefixes := []string{"db-primary", "db-replica", "db-analytics", "pg-master", "pg-slave", "mysql-primary"}
	return fmt.Sprintf("%s-%02d.prod.internal", g.RandomChoice(prefixes), g.RandomInt(1, 5))
}

func (g *DatabaseMetricsGenerator) randomDatabase() string {
	dbs := []string{"orders_db", "users_db", "inventory_db", "analytics_db", "sessions_db", "logs_db"}
	return g.RandomChoice(dbs)
}

func (g *DatabaseMetricsGenerator) randomDbEngine() string {
	engines := []string{"postgresql", "mysql", "mariadb", "oracle", "mssql"}
	return g.RandomChoice(engines)
}

func (g *DatabaseMetricsGenerator) randomRegion() string {
	regions := []string{"us-east-1", "us-west-2", "us-gov-east-1", "us-gov-west-1"}
	return g.RandomChoice(regions)
}

func (g *DatabaseMetricsGenerator) randomEnvironment() string {
	envs := []string{"production", "staging", "development"}
	return g.RandomChoice(envs)
}

func (g *DatabaseMetricsGenerator) randomCluster() string {
	clusters := []string{"primary-cluster", "analytics-cluster", "reporting-cluster"}
	return g.RandomChoice(clusters)
}

// buildMetricEvent creates a Splunk HEC metrics format event
func (g *DatabaseMetricsGenerator) buildMetricEvent(metricName string, value float64, dimensions map[string]string, timestamp time.Time) map[string]interface{} {
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
		"source": "database_metrics",
		"host":   dimensions["host"],
		"fields": fields,
	}
}

func (g *DatabaseMetricsGenerator) generateQueryPerformance(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	host := g.randomHost()
	database := g.randomDatabase()
	engine := g.randomDbEngine()
	region := g.randomRegion()
	env := g.randomEnvironment()

	dimensions := map[string]string{
		"host":        host,
		"database":    database,
		"engine":      engine,
		"region":      region,
		"environment": env,
	}

	// Query performance metrics
	metrics := []map[string]interface{}{
		// Query latency
		g.buildMetricEvent("db.query.latency.avg_ms", float64(g.RandomInt(1, 50))+float64(g.RandomInt(0, 99))/100, dimensions, timestamp),
		g.buildMetricEvent("db.query.latency.p50_ms", float64(g.RandomInt(1, 30))+float64(g.RandomInt(0, 99))/100, dimensions, timestamp),
		g.buildMetricEvent("db.query.latency.p90_ms", float64(g.RandomInt(10, 100))+float64(g.RandomInt(0, 99))/100, dimensions, timestamp),
		g.buildMetricEvent("db.query.latency.p95_ms", float64(g.RandomInt(20, 200))+float64(g.RandomInt(0, 99))/100, dimensions, timestamp),
		g.buildMetricEvent("db.query.latency.p99_ms", float64(g.RandomInt(50, 500))+float64(g.RandomInt(0, 99))/100, dimensions, timestamp),
		g.buildMetricEvent("db.query.latency.max_ms", float64(g.RandomInt(100, 5000))+float64(g.RandomInt(0, 99))/100, dimensions, timestamp),

		// Query throughput
		g.buildMetricEvent("db.query.rate", float64(g.RandomInt(100, 10000)), dimensions, timestamp),
		g.buildMetricEvent("db.query.select_rate", float64(g.RandomInt(50, 8000)), dimensions, timestamp),
		g.buildMetricEvent("db.query.insert_rate", float64(g.RandomInt(10, 2000)), dimensions, timestamp),
		g.buildMetricEvent("db.query.update_rate", float64(g.RandomInt(10, 1000)), dimensions, timestamp),
		g.buildMetricEvent("db.query.delete_rate", float64(g.RandomInt(1, 200)), dimensions, timestamp),

		// Slow queries
		g.buildMetricEvent("db.query.slow_count", float64(g.RandomInt(0, 50)), dimensions, timestamp),
		g.buildMetricEvent("db.query.timeout_count", float64(g.RandomInt(0, 5)), dimensions, timestamp),

		// Query plan metrics
		g.buildMetricEvent("db.query.full_scan_count", float64(g.RandomInt(0, 20)), dimensions, timestamp),
		g.buildMetricEvent("db.query.index_scan_count", float64(g.RandomInt(1000, 50000)), dimensions, timestamp),
	}

	// Per-table metrics
	tables := []string{"orders", "users", "products", "sessions", "audit_log"}
	for _, table := range tables {
		tableDimensions := map[string]string{
			"host":        host,
			"database":    database,
			"engine":      engine,
			"region":      region,
			"environment": env,
			"table":       table,
		}
		metrics = append(metrics,
			g.buildMetricEvent("db.table.rows_read", float64(g.RandomInt(1000, 1000000)), tableDimensions, timestamp),
			g.buildMetricEvent("db.table.rows_written", float64(g.RandomInt(100, 100000)), tableDimensions, timestamp),
			g.buildMetricEvent("db.table.seq_scans", float64(g.RandomInt(0, 100)), tableDimensions, timestamp),
			g.buildMetricEvent("db.table.index_scans", float64(g.RandomInt(100, 10000)), tableDimensions, timestamp),
		)
	}

	fields := map[string]interface{}{
		"metrics":     metrics,
		"host":        host,
		"database":    database,
		"engine":      engine,
		"region":      region,
		"environment": env,
	}

	fields = g.ApplyOverrides(fields, overrides)
	rawEvent, _ := json.MarshalIndent(metrics, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "metrics_database",
		EventID:    "query_performance",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "metrics",
	}, nil
}

func (g *DatabaseMetricsGenerator) generateConnections(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	host := g.randomHost()
	database := g.randomDatabase()
	engine := g.randomDbEngine()
	region := g.randomRegion()
	env := g.randomEnvironment()

	maxConnections := float64(g.RandomChoice([]string{"100", "200", "500", "1000"})[0]) * 2
	activePercent := float64(g.RandomInt(20, 80))
	active := maxConnections * activePercent / 100
	idle := maxConnections - active - float64(g.RandomInt(0, int(maxConnections/10)))
	waiting := float64(g.RandomInt(0, 10))

	dimensions := map[string]string{
		"host":        host,
		"database":    database,
		"engine":      engine,
		"region":      region,
		"environment": env,
	}

	metrics := []map[string]interface{}{
		g.buildMetricEvent("db.connections.max", maxConnections, dimensions, timestamp),
		g.buildMetricEvent("db.connections.active", active, dimensions, timestamp),
		g.buildMetricEvent("db.connections.idle", idle, dimensions, timestamp),
		g.buildMetricEvent("db.connections.waiting", waiting, dimensions, timestamp),
		g.buildMetricEvent("db.connections.utilization_percent", activePercent, dimensions, timestamp),
		g.buildMetricEvent("db.connections.aborted", float64(g.RandomInt(0, 10)), dimensions, timestamp),
		g.buildMetricEvent("db.connections.created_total", float64(g.RandomInt(1000, 100000)), dimensions, timestamp),
	}

	// Connection states
	states := []struct {
		state string
		count int
	}{
		{"active", int(active)},
		{"idle", int(idle)},
		{"idle_in_transaction", g.RandomInt(0, 20)},
		{"idle_in_transaction_aborted", g.RandomInt(0, 2)},
		{"disabled", 0},
	}

	for _, s := range states {
		stateDimensions := map[string]string{
			"host":        host,
			"database":    database,
			"engine":      engine,
			"region":      region,
			"environment": env,
			"state":       s.state,
		}
		metrics = append(metrics, g.buildMetricEvent("db.connections.by_state", float64(s.count), stateDimensions, timestamp))
	}

	// Per-user connections
	users := []string{"app_user", "admin", "readonly", "replication", "monitoring"}
	for _, user := range users {
		userDimensions := map[string]string{
			"host":        host,
			"database":    database,
			"engine":      engine,
			"region":      region,
			"environment": env,
			"user":        user,
		}
		userConns := float64(g.RandomInt(1, int(maxConnections/5)))
		if user == "app_user" {
			userConns = active * 0.8
		}
		metrics = append(metrics, g.buildMetricEvent("db.connections.by_user", userConns, userDimensions, timestamp))
	}

	fields := map[string]interface{}{
		"metrics":     metrics,
		"host":        host,
		"database":    database,
		"engine":      engine,
		"region":      region,
		"environment": env,
	}

	fields = g.ApplyOverrides(fields, overrides)
	rawEvent, _ := json.MarshalIndent(metrics, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "metrics_database",
		EventID:    "connections",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "metrics",
	}, nil
}

func (g *DatabaseMetricsGenerator) generateBufferPool(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	host := g.randomHost()
	database := g.randomDatabase()
	engine := g.randomDbEngine()
	region := g.randomRegion()
	env := g.randomEnvironment()

	// Buffer pool size (1GB to 64GB)
	bufferPoolSize := float64(g.RandomInt(1, 64)) * 1024 * 1024 * 1024
	usedPercent := float64(g.RandomInt(60, 95))
	usedBytes := bufferPoolSize * usedPercent / 100

	// Hit ratio should be high (95-99.9%)
	hitRatio := 95 + float64(g.RandomInt(0, 49))/10

	dimensions := map[string]string{
		"host":        host,
		"database":    database,
		"engine":      engine,
		"region":      region,
		"environment": env,
	}

	metrics := []map[string]interface{}{
		// Buffer pool size and usage
		g.buildMetricEvent("db.buffer.size_bytes", bufferPoolSize, dimensions, timestamp),
		g.buildMetricEvent("db.buffer.used_bytes", usedBytes, dimensions, timestamp),
		g.buildMetricEvent("db.buffer.used_percent", usedPercent, dimensions, timestamp),
		g.buildMetricEvent("db.buffer.free_bytes", bufferPoolSize-usedBytes, dimensions, timestamp),

		// Hit ratios
		g.buildMetricEvent("db.buffer.hit_ratio", hitRatio, dimensions, timestamp),
		g.buildMetricEvent("db.buffer.disk_reads", float64(g.RandomInt(100, 10000)), dimensions, timestamp),
		g.buildMetricEvent("db.buffer.buffer_reads", float64(g.RandomInt(100000, 10000000)), dimensions, timestamp),

		// Page metrics
		g.buildMetricEvent("db.buffer.pages_read", float64(g.RandomInt(1000, 100000)), dimensions, timestamp),
		g.buildMetricEvent("db.buffer.pages_written", float64(g.RandomInt(100, 50000)), dimensions, timestamp),
		g.buildMetricEvent("db.buffer.pages_dirty", float64(g.RandomInt(10, 10000)), dimensions, timestamp),
		g.buildMetricEvent("db.buffer.pages_flushed", float64(g.RandomInt(100, 50000)), dimensions, timestamp),

		// Checkpoint metrics
		g.buildMetricEvent("db.checkpoint.count", float64(g.RandomInt(10, 1000)), dimensions, timestamp),
		g.buildMetricEvent("db.checkpoint.write_time_ms", float64(g.RandomInt(100, 5000)), dimensions, timestamp),
		g.buildMetricEvent("db.checkpoint.sync_time_ms", float64(g.RandomInt(10, 1000)), dimensions, timestamp),
	}

	// Shared buffers breakdown (PostgreSQL specific)
	if engine == "postgresql" {
		metrics = append(metrics,
			g.buildMetricEvent("db.shared_buffers.total", bufferPoolSize, dimensions, timestamp),
			g.buildMetricEvent("db.shared_buffers.used", usedBytes, dimensions, timestamp),
			g.buildMetricEvent("db.effective_cache_size", bufferPoolSize*2, dimensions, timestamp),
		)
	}

	// InnoDB specific (MySQL)
	if engine == "mysql" || engine == "mariadb" {
		metrics = append(metrics,
			g.buildMetricEvent("db.innodb.buffer_pool_size", bufferPoolSize, dimensions, timestamp),
			g.buildMetricEvent("db.innodb.buffer_pool_pages_data", float64(g.RandomInt(10000, 1000000)), dimensions, timestamp),
			g.buildMetricEvent("db.innodb.buffer_pool_pages_free", float64(g.RandomInt(100, 10000)), dimensions, timestamp),
			g.buildMetricEvent("db.innodb.buffer_pool_read_requests", float64(g.RandomInt(1000000, 100000000)), dimensions, timestamp),
			g.buildMetricEvent("db.innodb.buffer_pool_reads", float64(g.RandomInt(1000, 100000)), dimensions, timestamp),
		)
	}

	fields := map[string]interface{}{
		"metrics":     metrics,
		"host":        host,
		"database":    database,
		"engine":      engine,
		"region":      region,
		"environment": env,
	}

	fields = g.ApplyOverrides(fields, overrides)
	rawEvent, _ := json.MarshalIndent(metrics, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "metrics_database",
		EventID:    "buffer_pool",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "metrics",
	}, nil
}

func (g *DatabaseMetricsGenerator) generateTransactions(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	host := g.randomHost()
	database := g.randomDatabase()
	engine := g.randomDbEngine()
	region := g.randomRegion()
	env := g.randomEnvironment()

	tps := float64(g.RandomInt(100, 5000))
	commits := tps * float64(g.RandomInt(95, 99)) / 100
	rollbacks := tps - commits

	dimensions := map[string]string{
		"host":        host,
		"database":    database,
		"engine":      engine,
		"region":      region,
		"environment": env,
	}

	metrics := []map[string]interface{}{
		// Transaction rates
		g.buildMetricEvent("db.transactions.rate", tps, dimensions, timestamp),
		g.buildMetricEvent("db.transactions.commits", commits, dimensions, timestamp),
		g.buildMetricEvent("db.transactions.rollbacks", rollbacks, dimensions, timestamp),
		g.buildMetricEvent("db.transactions.commit_rate_percent", (commits/tps)*100, dimensions, timestamp),

		// Transaction timing
		g.buildMetricEvent("db.transactions.avg_duration_ms", float64(g.RandomInt(5, 100)), dimensions, timestamp),
		g.buildMetricEvent("db.transactions.max_duration_ms", float64(g.RandomInt(100, 5000)), dimensions, timestamp),

		// Active transactions
		g.buildMetricEvent("db.transactions.active", float64(g.RandomInt(1, 100)), dimensions, timestamp),
		g.buildMetricEvent("db.transactions.long_running", float64(g.RandomInt(0, 5)), dimensions, timestamp),
		g.buildMetricEvent("db.transactions.oldest_age_seconds", float64(g.RandomInt(0, 300)), dimensions, timestamp),

		// WAL/Redo log metrics
		g.buildMetricEvent("db.wal.write_rate_bytes", float64(g.RandomInt(1000000, 100000000)), dimensions, timestamp),
		g.buildMetricEvent("db.wal.segments", float64(g.RandomInt(10, 100)), dimensions, timestamp),
	}

	// Totals
	metrics = append(metrics,
		g.buildMetricEvent("db.transactions.total_commits", float64(g.RandomInt(1000000, 1000000000)), dimensions, timestamp),
		g.buildMetricEvent("db.transactions.total_rollbacks", float64(g.RandomInt(10000, 10000000)), dimensions, timestamp),
	)

	fields := map[string]interface{}{
		"metrics":     metrics,
		"host":        host,
		"database":    database,
		"engine":      engine,
		"region":      region,
		"environment": env,
	}

	fields = g.ApplyOverrides(fields, overrides)
	rawEvent, _ := json.MarshalIndent(metrics, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "metrics_database",
		EventID:    "transactions",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "metrics",
	}, nil
}

func (g *DatabaseMetricsGenerator) generateReplication(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	host := g.randomHost()
	database := g.randomDatabase()
	engine := g.randomDbEngine()
	region := g.randomRegion()
	env := g.randomEnvironment()
	cluster := g.randomCluster()

	// Replication lag (0 to 60 seconds, usually low)
	lagSeconds := float64(g.RandomInt(0, 10)) + float64(g.RandomInt(0, 999))/1000
	if g.RandomInt(0, 20) > 18 { // 10% chance of higher lag
		lagSeconds = float64(g.RandomInt(10, 60))
	}

	dimensions := map[string]string{
		"host":        host,
		"database":    database,
		"engine":      engine,
		"region":      region,
		"environment": env,
		"cluster":     cluster,
		"role":        g.RandomChoice([]string{"primary", "replica"}),
	}

	metrics := []map[string]interface{}{
		// Replication lag
		g.buildMetricEvent("db.replication.lag_seconds", lagSeconds, dimensions, timestamp),
		g.buildMetricEvent("db.replication.lag_bytes", float64(g.RandomInt(0, 10000000)), dimensions, timestamp),

		// Replication state
		g.buildMetricEvent("db.replication.is_replica", func() float64 {
			if dimensions["role"] == "replica" {
				return 1
			}
			return 0
		}(), dimensions, timestamp),
		g.buildMetricEvent("db.replication.is_streaming", 1, dimensions, timestamp),

		// Throughput
		g.buildMetricEvent("db.replication.sent_bytes", float64(g.RandomInt(1000000, 1000000000)), dimensions, timestamp),
		g.buildMetricEvent("db.replication.received_bytes", float64(g.RandomInt(1000000, 1000000000)), dimensions, timestamp),
		g.buildMetricEvent("db.replication.replayed_bytes", float64(g.RandomInt(1000000, 1000000000)), dimensions, timestamp),

		// LSN/Position
		g.buildMetricEvent("db.replication.write_lag_bytes", float64(g.RandomInt(0, 100000)), dimensions, timestamp),
		g.buildMetricEvent("db.replication.flush_lag_bytes", float64(g.RandomInt(0, 50000)), dimensions, timestamp),
		g.buildMetricEvent("db.replication.replay_lag_bytes", float64(g.RandomInt(0, 100000)), dimensions, timestamp),
	}

	// Replica-specific metrics
	replicas := []string{"replica-01", "replica-02", "replica-03"}
	for _, replica := range replicas {
		replicaDimensions := map[string]string{
			"host":        host,
			"database":    database,
			"engine":      engine,
			"region":      region,
			"environment": env,
			"cluster":     cluster,
			"replica":     replica,
		}
		metrics = append(metrics,
			g.buildMetricEvent("db.replica.lag_seconds", float64(g.RandomInt(0, 5))+float64(g.RandomInt(0, 999))/1000, replicaDimensions, timestamp),
			g.buildMetricEvent("db.replica.state", 1, replicaDimensions, timestamp), // 1 = streaming
		)
	}

	fields := map[string]interface{}{
		"metrics":     metrics,
		"host":        host,
		"database":    database,
		"engine":      engine,
		"region":      region,
		"environment": env,
		"cluster":     cluster,
	}

	fields = g.ApplyOverrides(fields, overrides)
	rawEvent, _ := json.MarshalIndent(metrics, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "metrics_database",
		EventID:    "replication",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "metrics",
	}, nil
}

func (g *DatabaseMetricsGenerator) generateLocks(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	host := g.randomHost()
	database := g.randomDatabase()
	engine := g.randomDbEngine()
	region := g.randomRegion()
	env := g.randomEnvironment()

	dimensions := map[string]string{
		"host":        host,
		"database":    database,
		"engine":      engine,
		"region":      region,
		"environment": env,
	}

	metrics := []map[string]interface{}{
		// Lock counts
		g.buildMetricEvent("db.locks.total", float64(g.RandomInt(10, 500)), dimensions, timestamp),
		g.buildMetricEvent("db.locks.waiting", float64(g.RandomInt(0, 20)), dimensions, timestamp),
		g.buildMetricEvent("db.locks.granted", float64(g.RandomInt(10, 480)), dimensions, timestamp),

		// Lock wait time
		g.buildMetricEvent("db.locks.avg_wait_ms", float64(g.RandomInt(0, 100)), dimensions, timestamp),
		g.buildMetricEvent("db.locks.max_wait_ms", float64(g.RandomInt(0, 5000)), dimensions, timestamp),
		g.buildMetricEvent("db.locks.total_wait_ms", float64(g.RandomInt(0, 100000)), dimensions, timestamp),

		// Deadlocks
		g.buildMetricEvent("db.locks.deadlocks", float64(g.RandomInt(0, 5)), dimensions, timestamp),
		g.buildMetricEvent("db.locks.deadlocks_total", float64(g.RandomInt(0, 100)), dimensions, timestamp),

		// Lock timeouts
		g.buildMetricEvent("db.locks.timeouts", float64(g.RandomInt(0, 10)), dimensions, timestamp),
	}

	// Lock types
	lockTypes := []struct {
		lockType string
		weight   int
	}{
		{"AccessShareLock", 50},
		{"RowShareLock", 20},
		{"RowExclusiveLock", 30},
		{"ShareUpdateExclusiveLock", 5},
		{"ShareLock", 10},
		{"ShareRowExclusiveLock", 3},
		{"ExclusiveLock", 2},
		{"AccessExclusiveLock", 1},
	}

	for _, lt := range lockTypes {
		lockDimensions := map[string]string{
			"host":        host,
			"database":    database,
			"engine":      engine,
			"region":      region,
			"environment": env,
			"lock_type":   lt.lockType,
		}
		metrics = append(metrics,
			g.buildMetricEvent("db.locks.by_type", float64(g.RandomInt(0, lt.weight*10)), lockDimensions, timestamp),
		)
	}

	// Blocking sessions
	metrics = append(metrics,
		g.buildMetricEvent("db.blocking.sessions", float64(g.RandomInt(0, 5)), dimensions, timestamp),
		g.buildMetricEvent("db.blocking.oldest_seconds", float64(g.RandomInt(0, 60)), dimensions, timestamp),
	)

	fields := map[string]interface{}{
		"metrics":     metrics,
		"host":        host,
		"database":    database,
		"engine":      engine,
		"region":      region,
		"environment": env,
	}

	fields = g.ApplyOverrides(fields, overrides)
	rawEvent, _ := json.MarshalIndent(metrics, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "metrics_database",
		EventID:    "locks",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "metrics",
	}, nil
}

func (g *DatabaseMetricsGenerator) generateTablespace(overrides map[string]interface{}) (*models.GeneratedEvent, error) {
	timestamp := time.Now()
	host := g.randomHost()
	database := g.randomDatabase()
	engine := g.randomDbEngine()
	region := g.randomRegion()
	env := g.randomEnvironment()

	tablespaces := []struct {
		name   string
		sizeGB int
	}{
		{"pg_default", 500},
		{"pg_global", 10},
		{"data_tablespace", 1000},
		{"index_tablespace", 200},
		{"archive_tablespace", 2000},
	}

	metrics := make([]map[string]interface{}, 0)

	totalSize := 0.0
	totalUsed := 0.0

	for _, ts := range tablespaces {
		sizeBytes := float64(ts.sizeGB) * 1024 * 1024 * 1024
		usedPercent := float64(g.RandomInt(30, 90))
		usedBytes := sizeBytes * usedPercent / 100
		freeBytes := sizeBytes - usedBytes

		totalSize += sizeBytes
		totalUsed += usedBytes

		dimensions := map[string]string{
			"host":        host,
			"database":    database,
			"engine":      engine,
			"region":      region,
			"environment": env,
			"tablespace":  ts.name,
		}

		metrics = append(metrics,
			g.buildMetricEvent("db.tablespace.size_bytes", sizeBytes, dimensions, timestamp),
			g.buildMetricEvent("db.tablespace.used_bytes", usedBytes, dimensions, timestamp),
			g.buildMetricEvent("db.tablespace.free_bytes", freeBytes, dimensions, timestamp),
			g.buildMetricEvent("db.tablespace.used_percent", usedPercent, dimensions, timestamp),
		)
	}

	// Database-level totals
	dbDimensions := map[string]string{
		"host":        host,
		"database":    database,
		"engine":      engine,
		"region":      region,
		"environment": env,
	}

	metrics = append(metrics,
		g.buildMetricEvent("db.size.total_bytes", totalSize, dbDimensions, timestamp),
		g.buildMetricEvent("db.size.used_bytes", totalUsed, dbDimensions, timestamp),
		g.buildMetricEvent("db.size.used_percent", (totalUsed/totalSize)*100, dbDimensions, timestamp),
	)

	// Table sizes (top tables)
	tables := []struct {
		name   string
		sizeGB int
	}{
		{"orders", 200},
		{"order_items", 150},
		{"audit_log", 500},
		{"users", 50},
		{"sessions", 100},
		{"products", 30},
		{"inventory", 20},
	}

	for _, table := range tables {
		tableDimensions := map[string]string{
			"host":        host,
			"database":    database,
			"engine":      engine,
			"region":      region,
			"environment": env,
			"table":       table.name,
		}
		tableSize := float64(table.sizeGB) * float64(g.RandomInt(80, 120)) / 100 * 1024 * 1024 * 1024
		indexSize := tableSize * float64(g.RandomInt(20, 50)) / 100
		rowCount := float64(g.RandomInt(100000, 100000000))

		metrics = append(metrics,
			g.buildMetricEvent("db.table.size_bytes", tableSize, tableDimensions, timestamp),
			g.buildMetricEvent("db.table.index_size_bytes", indexSize, tableDimensions, timestamp),
			g.buildMetricEvent("db.table.total_size_bytes", tableSize+indexSize, tableDimensions, timestamp),
			g.buildMetricEvent("db.table.row_count", rowCount, tableDimensions, timestamp),
			g.buildMetricEvent("db.table.dead_tuples", float64(g.RandomInt(0, 10000)), tableDimensions, timestamp),
		)
	}

	fields := map[string]interface{}{
		"metrics":     metrics,
		"host":        host,
		"database":    database,
		"engine":      engine,
		"region":      region,
		"environment": env,
	}

	fields = g.ApplyOverrides(fields, overrides)
	rawEvent, _ := json.MarshalIndent(metrics, "", "  ")

	return &models.GeneratedEvent{
		ID:         uuid.New().String(),
		Type:       "metrics_database",
		EventID:    "tablespace",
		Timestamp:  timestamp,
		RawEvent:   string(rawEvent),
		Fields:     fields,
		Sourcetype: "metrics",
	}, nil
}
