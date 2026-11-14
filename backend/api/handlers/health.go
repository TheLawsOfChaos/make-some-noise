package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// Version is set at build time with -ldflags "-X siem-event-generator/api/handlers.Version=x.y.z".
var Version = "dev"

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
		Version:   Version,
		Uptime:    uptime,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	c.JSON(http.StatusOK, response)
}
