package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"siem-event-generator/models"
	"siem-event-generator/noise"
)

// StartNoiseGeneration starts continuous noise generation
func StartNoiseGeneration(c *gin.Context) {
	var req models.NoiseStartRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate rate
	if req.RatePerSecond < 0.1 || req.RatePerSecond > 10000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "rate_per_second must be between 0.1 and 10000"})
		return
	}

	// Validate enabled sources
	if len(req.EnabledSources) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "at least one enabled source is required"})
		return
	}

	hasEnabled := false
	for _, source := range req.EnabledSources {
		if source.Enabled {
			hasEnabled = true
			break
		}
	}
	if !hasEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "at least one source must be enabled"})
		return
	}

	// Collect all unique destination IDs needed
	destinationIDs := make(map[string]bool)

	// Add global fallback destination if set
	if req.DestinationID != "" {
		destinationIDs[req.DestinationID] = true
	}

	// Add per-source destinations
	for _, source := range req.EnabledSources {
		if source.Enabled && source.DestinationID != "" {
			destinationIDs[source.DestinationID] = true
		}
	}

	// Ensure at least one destination is configured
	if len(destinationIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "at least one destination must be configured (global or per-source)"})
		return
	}

	// Fetch all required destinations
	destinations := make(map[string]*models.Destination)
	for destID := range destinationIDs {
		dest, exists := destinationStore.Get(destID)
		if !exists {
			c.JSON(http.StatusNotFound, gin.H{"error": "destination not found: " + destID})
			return
		}
		destinations[destID] = dest
	}

	config := &models.NoiseConfig{
		DestinationID:  req.DestinationID,
		RatePerSecond:  req.RatePerSecond,
		EnabledSources: req.EnabledSources,
	}

	gen := noise.GetInstance()
	if err := gen.Start(config, destinations); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Noise generation started",
		"status":  gen.GetStatus(),
	})
}

// StopNoiseGeneration stops noise generation
func StopNoiseGeneration(c *gin.Context) {
	gen := noise.GetInstance()
	if err := gen.Stop(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Noise generation stopped",
		"status":  gen.GetStatus(),
	})
}

// GetNoiseStatus returns the current noise generation status
func GetNoiseStatus(c *gin.Context) {
	gen := noise.GetInstance()
	c.JSON(http.StatusOK, gen.GetStatus())
}

// UpdateNoiseConfig updates the running noise configuration
func UpdateNoiseConfig(c *gin.Context) {
	var req models.NoiseUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate rate if provided
	if req.RatePerSecond != nil && (*req.RatePerSecond < 0.1 || *req.RatePerSecond > 10000) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "rate_per_second must be between 0.1 and 10000"})
		return
	}

	gen := noise.GetInstance()
	if err := gen.UpdateConfig(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"status":  gen.GetStatus(),
	})
}

// GetNoiseStats returns the current noise generation statistics
func GetNoiseStats(c *gin.Context) {
	gen := noise.GetInstance()
	status := gen.GetStatus()
	c.JSON(http.StatusOK, status.Stats)
}
