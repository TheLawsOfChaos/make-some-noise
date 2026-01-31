package main

import (
	"log"
	"os"

	"siem-event-generator/api"
	"siem-event-generator/api/handlers"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Ensure config directory exists
	configDir := os.Getenv("CONFIG_DIR")
	if configDir == "" {
		configDir = "/config"
	}
	if err := os.MkdirAll(configDir, 0755); err != nil {
		log.Printf("WARNING: could not create config dir %s: %v", configDir, err)
	}

	// Load persisted configurations
	if err := handlers.LoadDestinations(); err != nil {
		log.Printf("WARNING: failed to load destinations: %v", err)
	}
	handlers.SeedDefaultDestinationIfEmpty()

	if err := handlers.LoadTemplates(); err != nil {
		log.Printf("WARNING: failed to load templates: %v", err)
	}

	router := api.SetupRouter()

	log.Printf("SIEM Event Generator API starting on port %s", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
