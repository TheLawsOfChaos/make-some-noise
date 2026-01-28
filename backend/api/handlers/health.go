package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

var startTime = time.Now()

// HealthResponse represents the health check response
type HealthResponse struct {
	Status    string `json:"status"`
	Version   string `json:"version"`
	Uptime    string `json:"uptime"`
	Timestamp string `json:"timestamp"`
}

// HealthCheck returns the health status of the API
func HealthCheck(c *gin.Context) {
	uptime := time.Since(startTime).Round(time.Second).String()

	response := HealthResponse{
		Status:    "healthy",
		Version:   "1.0.0",
		Uptime:    uptime,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	c.JSON(http.StatusOK, response)
}
