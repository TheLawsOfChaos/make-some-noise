package api

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"siem-event-generator/api/handlers"
)

// SetupRouter configures and returns the Gin router
func SetupRouter() *gin.Engine {
	router := gin.Default()

	// Configure CORS
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://localhost:3000", "http://localhost:5173"}
	config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization"}
	router.Use(cors.New(config))

	// API routes
	api := router.Group("/api")
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
