package api

import (
	"crypto/subtle"
	"net/http"
	"os"
	"strings"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"siem-event-generator/api/handlers"
)

// bearerAuth requires "Authorization: Bearer <token>" on every route in the
// group when token is non-empty. /api/health stays open for health checks.
func bearerAuth(token string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if token == "" || c.Request.URL.Path == "/api/health" {
			c.Next()
			return
		}
		got := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid API token"})
			return
		}
		c.Next()
	}
}

// SetupRouter configures and returns the Gin router
func SetupRouter() *gin.Engine {
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.Default()

	// Configure CORS
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://localhost:3000", "http://localhost:5173"}
	config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization"}
	router.Use(cors.New(config))

	// API routes
	api := router.Group("/api")
	api.Use(bearerAuth(os.Getenv("API_TOKEN")))
	{
		// Health check
		api.GET("/health", handlers.HealthCheck)

		// Event types
		api.GET("/event-types", handlers.ListEventTypes)
		api.GET("/event-types/:type/schema", handlers.GetEventTypeSchema)

		// Event generation
		api.POST("/generate", handlers.GenerateEvents)
		api.POST("/generate/preview", handlers.PreviewEvent)

		// Destinations
		api.GET("/destinations", handlers.ListDestinations)
		api.POST("/destinations", handlers.CreateDestination)
		api.GET("/destinations/:id", handlers.GetDestination)
		api.PUT("/destinations/:id", handlers.UpdateDestination)
		api.DELETE("/destinations/:id", handlers.DeleteDestination)
		api.POST("/destinations/:id/test", handlers.TestDestination)
		api.POST("/destinations/test", handlers.TestDestinationConfig)

		// Templates
		api.GET("/templates", handlers.ListTemplates)
		api.GET("/templates/:id", handlers.GetTemplate)
		api.POST("/templates", handlers.CreateTemplate)
		api.PUT("/templates/:id", handlers.UpdateTemplate)
		api.DELETE("/templates/:id", handlers.DeleteTemplate)

		// Event sources (for noise generator UI)
		api.GET("/event-sources", handlers.GetEventSources)

		// Noise generation
		api.POST("/noise/start", handlers.StartNoiseGeneration)
		api.POST("/noise/stop", handlers.StopNoiseGeneration)
		api.GET("/noise/status", handlers.GetNoiseStatus)
		api.PUT("/noise/config", handlers.UpdateNoiseConfig)
		api.GET("/noise/stats", handlers.GetNoiseStats)
	}

	return router
}
