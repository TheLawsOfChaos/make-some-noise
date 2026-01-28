package handlers

import (
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"

	"siem-event-generator/delivery"
	"siem-event-generator/generators"
	"siem-event-generator/models"
)

// ListEventTypes returns all available event types
func ListEventTypes(c *gin.Context) {
	eventTypes := generators.GetAllEventTypes()
	c.JSON(http.StatusOK, gin.H{
		"event_types": eventTypes,
		"count":       len(eventTypes),
	})
}

// GetEventTypeSchema returns the schema for a specific event type
func GetEventTypeSchema(c *gin.Context) {
	eventType := c.Param("type")

	gen, ok := generators.GetGenerator(eventType)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Event type not found",
		})
		return
	}

	schema := models.EventTypeSchema{
		EventType: gen.GetEventType(),
		Templates: gen.GetTemplates(),
	}

	c.JSON(http.StatusOK, schema)
}

// GenerateEvents generates events based on the request
func GenerateEvents(c *gin.Context) {
	var req models.GenerateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	gen, ok := generators.GetGenerator(req.EventType)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Event type not found",
		})
		return
	}

	// Generate events
	events := make([]*models.GeneratedEvent, 0, req.Count)
	errors := make([]string, 0)

	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, 10) // Limit concurrent generation

	for i := 0; i < req.Count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			templateID := req.EventID
			if templateID == "" {
				// Use first available template if not specified
				templates := gen.GetTemplates()
				if len(templates) > 0 {
					templateID = templates[0].ID
				}
			}

			event, err := gen.Generate(templateID, req.Overrides)
			if err != nil {
				mu.Lock()
				errors = append(errors, err.Error())
				mu.Unlock()
				return
			}

			mu.Lock()
			events = append(events, event)
			mu.Unlock()
		}()
	}

	wg.Wait()

	// Send to destination if specified
	var eventsSent int
	var destinationName string

	if req.DestinationID != "" {
		dest, exists := destinationStore.Get(req.DestinationID)
		if exists {
			destinationName = dest.Name
			sender, err := delivery.GetSender(dest)
			if err != nil {
				errors = append(errors, "Failed to create sender: "+err.Error())
			} else {
				for _, event := range events {
					if err := sender.Send(event); err != nil {
						errors = append(errors, "Send error: "+err.Error())
					} else {
						eventsSent++
					}
				}
				sender.Close()
			}
		} else {
			errors = append(errors, "Destination not found")
		}
	}

	// Prepare preview (limit to 5 events)
	preview := make([]models.GeneratedEvent, 0)
	for i := 0; i < len(events) && i < 5; i++ {
		preview = append(preview, *events[i])
	}

	response := models.GenerateResponse{
		Success:       len(errors) == 0,
		EventsCreated: len(events),
		EventsSent:    eventsSent,
		Destination:   destinationName,
		Errors:        errors,
		Preview:       preview,
	}

	c.JSON(http.StatusOK, response)
}

// PreviewEvent generates a single event for preview
func PreviewEvent(c *gin.Context) {
	var req models.PreviewRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	gen, ok := generators.GetGenerator(req.EventType)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Event type not found",
		})
		return
	}

	templateID := req.EventID
	if templateID == "" {
		templates := gen.GetTemplates()
		if len(templates) > 0 {
			templateID = templates[0].ID
		}
	}

	event, err := gen.Generate(templateID, req.Overrides)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, event)
}

// GetEventSources returns all event types with their templates in a hierarchical structure
func GetEventSources(c *gin.Context) {
	tree := models.EventSourceTree{
		Categories: make(map[string][]models.EventSourceInfo),
	}

	for _, gen := range generators.Registry {
		eventType := gen.GetEventType()
		templates := gen.GetTemplates()

		info := models.EventSourceInfo{
			EventType: eventType,
			Templates: templates,
		}

		tree.Categories[eventType.Category] = append(
			tree.Categories[eventType.Category],
			info,
		)
	}

	c.JSON(http.StatusOK, tree)
}
