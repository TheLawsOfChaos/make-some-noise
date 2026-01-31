package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"siem-event-generator/models"
)

// configDir returns the config directory path from env or default
func configDir() string {
	dir := os.Getenv("CONFIG_DIR")
	if dir == "" {
		dir = "/config"
	}
	return dir
}

// atomicWriteJSON writes data as indented JSON to filePath atomically
func atomicWriteJSON(filePath string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	tmpPath := filePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := os.Rename(tmpPath, filePath); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// SaveDestinations persists the destination store to disk
func SaveDestinations() {
	path := filepath.Join(configDir(), "destinations.json")
	if err := atomicWriteJSON(path, destinationStore.List()); err != nil {
		log.Printf("WARNING: failed to save destinations: %v", err)
	}
}

// LoadDestinations loads destinations from disk into the store
func LoadDestinations() error {
	path := filepath.Join(configDir(), "destinations.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read destinations: %w", err)
	}

	var dests []*models.Destination
	if err := json.Unmarshal(data, &dests); err != nil {
		return fmt.Errorf("parse destinations: %w", err)
	}

	for _, d := range dests {
		destinationStore.Create(d)
	}
	return nil
}

// SeedDefaultDestinationIfEmpty adds the default file destination when the store is empty
func SeedDefaultDestinationIfEmpty() {
	if len(destinationStore.List()) > 0 {
		return
	}

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

// SaveTemplates persists the custom template store to disk
func SaveTemplates() {
	path := filepath.Join(configDir(), "templates.json")
	if err := atomicWriteJSON(path, templateStore.List()); err != nil {
		log.Printf("WARNING: failed to save templates: %v", err)
	}
}

// LoadTemplates loads custom templates from disk into the store
func LoadTemplates() error {
	path := filepath.Join(configDir(), "templates.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read templates: %w", err)
	}

	var tmpls []*models.EventTemplate
	if err := json.Unmarshal(data, &tmpls); err != nil {
		return fmt.Errorf("parse templates: %w", err)
	}

	for _, t := range tmpls {
		templateStore.Create(t)
	}
	return nil
}
