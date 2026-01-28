package handlers

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"siem-event-generator/delivery"
	"siem-event-generator/models"
)

// DestinationStore provides thread-safe destination storage
type DestinationStore struct {
	mu           sync.RWMutex
	destinations map[string]*models.Destination
}

// NewDestinationStore creates a new destination store
func NewDestinationStore() *DestinationStore {
	return &DestinationStore{
		destinations: make(map[string]*models.Destination),
	}
}

// Get retrieves a destination by ID
func (s *DestinationStore) Get(id string) (*models.Destination, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	dest, ok := s.destinations[id]
	return dest, ok
}

// List returns all destinations
func (s *DestinationStore) List() []*models.Destination {
	s.mu.RLock()
	defer s.mu.RUnlock()
	dests := make([]*models.Destination, 0, len(s.destinations))
	for _, d := range s.destinations {
		dests = append(dests, d)
	}
	return dests
}

// Create adds a new destination
func (s *DestinationStore) Create(dest *models.Destination) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.destinations[dest.ID] = dest
}

// Update modifies an existing destination
func (s *DestinationStore) Update(dest *models.Destination) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.destinations[dest.ID]; !ok {
		return false
	}
	s.destinations[dest.ID] = dest
	return true
}

// Delete removes a destination
func (s *DestinationStore) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.destinations[id]; !ok {
		return false
	}
	delete(s.destinations, id)
	return true
}

// Global destination store (in production, use a database)
var destinationStore = NewDestinationStore()

func init() {
	// Create a default file destination
	defaultDest := &models.Destination{
		ID:          "default-file",
		Name:        "Local File Output",
		Type:        models.DestinationTypeFile,
		Description: "Default file output destination",
		Config: models.DestinationConfig{
			FilePath:   "/tmp/output/siem-events.log",
			MaxSizeMB:  100,
			RotateKeep: 5,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	destinationStore.Create(defaultDest)
}

// ListDestinations returns all destinations
func ListDestinations(c *gin.Context) {
	destinations := destinationStore.List()
	c.JSON(http.StatusOK, gin.H{
		"destinations": destinations,
		"count":        len(destinations),
	})
}

// GetDestination returns a specific destination
func GetDestination(c *gin.Context) {
	id := c.Param("id")

	dest, ok := destinationStore.Get(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Destination not found",
		})
		return
	}

	c.JSON(http.StatusOK, dest)
}

// CreateDestination creates a new destination
func CreateDestination(c *gin.Context) {
	var dest models.Destination
	if err := c.ShouldBindJSON(&dest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	dest.ID = uuid.New().String()
	dest.CreatedAt = time.Now()
	dest.UpdatedAt = time.Now()

	destinationStore.Create(&dest)

	c.JSON(http.StatusCreated, dest)
}

// UpdateDestination updates an existing destination
func UpdateDestination(c *gin.Context) {
	id := c.Param("id")

	existing, ok := destinationStore.Get(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Destination not found",
		})
		return
	}

	var dest models.Destination
	if err := c.ShouldBindJSON(&dest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	dest.ID = id
	dest.CreatedAt = existing.CreatedAt
	dest.UpdatedAt = time.Now()
	dest.EventsSent = existing.EventsSent

	destinationStore.Update(&dest)

	c.JSON(http.StatusOK, dest)
}

// DeleteDestination removes a destination
func DeleteDestination(c *gin.Context) {
	id := c.Param("id")

	if !destinationStore.Delete(id) {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Destination not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Destination deleted",
	})
}

// TestDestination tests a saved destination connection
func TestDestination(c *gin.Context) {
	id := c.Param("id")

	dest, ok := destinationStore.Get(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Destination not found",
		})
		return
	}

	response := testDestinationConnection(dest)
	c.JSON(http.StatusOK, response)
}

// TestDestinationConfig tests a destination configuration without saving
func TestDestinationConfig(c *gin.Context) {
	var req models.TestConnectionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	dest := &models.Destination{
		Type:   req.Type,
		Config: req.Config,
	}

	response := testDestinationConnection(dest)
	c.JSON(http.StatusOK, response)
}

// testDestinationConnection performs the actual connection test
func testDestinationConnection(dest *models.Destination) models.TestConnectionResponse {
	startTime := time.Now()

	sender, err := delivery.GetSender(dest)
	if err != nil {
		return models.TestConnectionResponse{
			Success: false,
			Message: "Failed to create sender",
			Error:   err.Error(),
		}
	}
	defer sender.Close()

	// Test the connection
	if err := sender.Test(); err != nil {
		return models.TestConnectionResponse{
			Success:   false,
			Message:   "Connection test failed",
			Error:     err.Error(),
			LatencyMs: time.Since(startTime).Milliseconds(),
		}
	}

	return models.TestConnectionResponse{
		Success:   true,
		Message:   "Connection successful",
		LatencyMs: time.Since(startTime).Milliseconds(),
	}
}
