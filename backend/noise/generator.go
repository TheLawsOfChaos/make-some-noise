package noise

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"siem-event-generator/delivery"
	"siem-event-generator/generators"
	"siem-event-generator/models"
)

// Generator manages continuous noise generation
type Generator struct {
	mu        sync.RWMutex
	running   bool
	ctx       context.Context
	cancel    context.CancelFunc
	config    *models.NoiseConfig
	stats     *models.NoiseStats
	senders   map[string]delivery.Sender // destination_id -> Sender
	startedAt time.Time

	// Weighted selection cache
	weightedPool []weightedTemplate
	totalWeight  int
}

type weightedTemplate struct {
	eventTypeID   string
	templateID    string
	destinationID string
	weight        int
}

// Global singleton instance
var instance *Generator
var once sync.Once

// GetInstance returns the singleton noise generator instance
func GetInstance() *Generator {
	once.Do(func() {
		instance = &Generator{
			stats: &models.NoiseStats{
				ByEventType: make(map[string]int64),
				ByTemplate:  make(map[string]int64),
			},
			senders: make(map[string]delivery.Sender),
		}
	})
	return instance
}

// Start begins continuous noise generation
func (g *Generator) Start(config *models.NoiseConfig, destinations map[string]*models.Destination) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.running {
		return fmt.Errorf("noise generation already running")
	}

	// Create senders for each destination
	g.senders = make(map[string]delivery.Sender)
	for id, dest := range destinations {
		sender, err := delivery.GetSender(dest)
		if err != nil {
			// Close any already-created senders
			for _, s := range g.senders {
				s.Close()
			}
			g.senders = nil
			return fmt.Errorf("failed to create sender for destination %s: %w", id, err)
		}
		g.senders[id] = sender
	}

	g.config = config
	g.ctx, g.cancel = context.WithCancel(context.Background())
	g.startedAt = time.Now()
	g.running = true

	// Reset stats
	g.stats = &models.NoiseStats{
		ByEventType:  make(map[string]int64),
		ByTemplate:   make(map[string]int64),
		ErrorSamples: make([]string, 0, 5),
	}

	// Build weighted pool
	g.buildWeightedPool()

	if len(g.weightedPool) == 0 {
		g.running = false
		for _, s := range g.senders {
			s.Close()
		}
		g.senders = nil
		return fmt.Errorf("no valid event sources enabled")
	}

	// Start generation goroutine
	go g.generateLoop()

	return nil
}

// Stop ends noise generation
func (g *Generator) Stop() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if !g.running {
		return fmt.Errorf("noise generation not running")
	}

	g.cancel()
	g.running = false

	// Close all senders
	for _, sender := range g.senders {
		sender.Close()
	}
	g.senders = nil

	return nil
}

// IsRunning returns whether noise generation is active
func (g *Generator) IsRunning() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.running
}

// GetStatus returns the current noise generation status
func (g *Generator) GetStatus() models.NoiseStatus {
	g.mu.RLock()
	defer g.mu.RUnlock()

	status := models.NoiseStatus{
		Running: g.running,
		Stats:   g.copyStats(),
	}

	if g.running {
		startedAt := g.startedAt
		status.StartedAt = &startedAt
		status.CurrentConfig = g.config
		status.Stats.DurationSeconds = int64(time.Since(g.startedAt).Seconds())

		// Calculate events per second
		if status.Stats.DurationSeconds > 0 {
			status.Stats.EventsPerSecond = float64(status.Stats.TotalSent) / float64(status.Stats.DurationSeconds)
		}
	}

	return status
}

// UpdateConfig updates the running configuration
func (g *Generator) UpdateConfig(update *models.NoiseUpdateRequest) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if !g.running {
		return fmt.Errorf("noise generation not running")
	}

	if update.RatePerSecond != nil {
		g.config.RatePerSecond = *update.RatePerSecond
	}

	if update.EnabledSources != nil {
		g.config.EnabledSources = update.EnabledSources
		g.buildWeightedPool()
	}

	return nil
}

func (g *Generator) generateLoop() {
	// Calculate interval between events
	interval := time.Duration(float64(time.Second) / g.config.RatePerSecond)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-g.ctx.Done():
			return
		case <-ticker.C:
			g.generateAndSend()

			// Check if rate changed and update ticker
			g.mu.RLock()
			newInterval := time.Duration(float64(time.Second) / g.config.RatePerSecond)
			g.mu.RUnlock()

			if newInterval != interval {
				interval = newInterval
				ticker.Reset(interval)
			}
		}
	}
}

func (g *Generator) generateAndSend() {
	g.mu.RLock()
	if len(g.weightedPool) == 0 {
		g.mu.RUnlock()
		return
	}

	// Select random template based on weight
	selected := g.selectWeighted()

	// Get the sender for this event's destination
	sender, ok := g.senders[selected.destinationID]
	g.mu.RUnlock()

	if !ok {
		atomic.AddInt64(&g.stats.TotalErrors, 1)
		g.addErrorSample(fmt.Sprintf("sender not found for destination: %s", selected.destinationID))
		return
	}

	// Get generator and generate event
	gen, ok := generators.GetGenerator(selected.eventTypeID)
	if !ok {
		atomic.AddInt64(&g.stats.TotalErrors, 1)
		g.addErrorSample(fmt.Sprintf("generator not found: %s", selected.eventTypeID))
		return
	}

	event, err := gen.Generate(selected.templateID, nil)
	if err != nil {
		atomic.AddInt64(&g.stats.TotalErrors, 1)
		g.addErrorSample(fmt.Sprintf("generate error: %v", err))
		return
	}

	atomic.AddInt64(&g.stats.TotalGenerated, 1)

	// Send to destination
	if err := sender.Send(event); err != nil {
		atomic.AddInt64(&g.stats.TotalErrors, 1)
		g.addErrorSample(fmt.Sprintf("send error: %v", err))
	} else {
		atomic.AddInt64(&g.stats.TotalSent, 1)
	}

	// Update per-type and per-template stats
	g.mu.Lock()
	g.stats.ByEventType[selected.eventTypeID]++
	g.stats.ByTemplate[selected.templateID]++
	now := time.Now()
	g.stats.LastEventAt = &now
	g.mu.Unlock()
}

func (g *Generator) selectWeighted() weightedTemplate {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(g.totalWeight)))
	target := int(n.Int64())

	cumulative := 0
	for _, wt := range g.weightedPool {
		cumulative += wt.weight
		if target < cumulative {
			return wt
		}
	}
	return g.weightedPool[len(g.weightedPool)-1]
}

func (g *Generator) buildWeightedPool() {
	g.weightedPool = nil
	g.totalWeight = 0

	for _, source := range g.config.EnabledSources {
		if !source.Enabled {
			continue
		}

		gen, ok := generators.GetGenerator(source.EventTypeID)
		if !ok {
			continue
		}

		// Determine destination for this source
		destinationID := source.DestinationID
		if destinationID == "" {
			destinationID = g.config.DestinationID // Use global fallback
		}
		if destinationID == "" {
			continue // No destination configured
		}

		// Verify sender exists for this destination
		if _, ok := g.senders[destinationID]; !ok {
			continue
		}

		templates := gen.GetTemplates()
		templateIDs := source.TemplateIDs

		// If no specific templates, use all
		if len(templateIDs) == 0 {
			for _, t := range templates {
				templateIDs = append(templateIDs, t.ID)
			}
		}

		// Set default weight if not specified
		weight := source.Weight
		if weight <= 0 {
			weight = 10
		}

		// Distribute weight among templates
		weightPerTemplate := weight
		if len(templateIDs) > 1 {
			weightPerTemplate = weight / len(templateIDs)
			if weightPerTemplate < 1 {
				weightPerTemplate = 1
			}
		}

		for _, tid := range templateIDs {
			// Verify template exists
			templateExists := false
			for _, t := range templates {
				if t.ID == tid {
					templateExists = true
					break
				}
			}
			if !templateExists {
				continue
			}

			g.weightedPool = append(g.weightedPool, weightedTemplate{
				eventTypeID:   source.EventTypeID,
				templateID:    tid,
				destinationID: destinationID,
				weight:        weightPerTemplate,
			})
			g.totalWeight += weightPerTemplate
		}
	}
}

func (g *Generator) addErrorSample(err string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if len(g.stats.ErrorSamples) >= 5 {
		g.stats.ErrorSamples = g.stats.ErrorSamples[1:]
	}
	g.stats.ErrorSamples = append(g.stats.ErrorSamples, err)
}

func (g *Generator) copyStats() models.NoiseStats {
	stats := models.NoiseStats{
		TotalGenerated:  atomic.LoadInt64(&g.stats.TotalGenerated),
		TotalSent:       atomic.LoadInt64(&g.stats.TotalSent),
		TotalErrors:     atomic.LoadInt64(&g.stats.TotalErrors),
		EventsPerSecond: g.stats.EventsPerSecond,
		DurationSeconds: g.stats.DurationSeconds,
		ByEventType:     make(map[string]int64),
		ByTemplate:      make(map[string]int64),
		ErrorSamples:    make([]string, len(g.stats.ErrorSamples)),
	}

	if g.stats.LastEventAt != nil {
		lastEvent := *g.stats.LastEventAt
		stats.LastEventAt = &lastEvent
	}

	for k, v := range g.stats.ByEventType {
		stats.ByEventType[k] = v
	}
	for k, v := range g.stats.ByTemplate {
		stats.ByTemplate[k] = v
	}
	copy(stats.ErrorSamples, g.stats.ErrorSamples)

	return stats
}
