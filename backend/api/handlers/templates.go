package handlers

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"siem-event-generator/generators"
	"siem-event-generator/models"
)

// TemplateStore provides thread-safe custom template storage
type TemplateStore struct {
	mu        sync.RWMutex
	templates map[string]*models.EventTemplate
}

// NewTemplateStore creates a new template store
func NewTemplateStore() *TemplateStore {
	return &TemplateStore{
		templates: make(map[string]*models.EventTemplate),
	}
}

// Get retrieves a template by ID
func (s *TemplateStore) Get(id string) (*models.EventTemplate, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tmpl, ok := s.templates[id]
	return tmpl, ok
}

// List returns all custom templates
func (s *TemplateStore) List() []*models.EventTemplate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tmpls := make([]*models.EventTemplate, 0, len(s.templates))
	for _, t := range s.templates {
		tmpls = append(tmpls, t)
	}
	return tmpls
}

// Create adds a new template
func (s *TemplateStore) Create(tmpl *models.EventTemplate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.templates[tmpl.ID] = tmpl
}

// Update modifies an existing template
func (s *TemplateStore) Update(tmpl *models.EventTemplate) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.templates[tmpl.ID]; !ok {
		return false
	}
	s.templates[tmpl.ID] = tmpl
	return true
}

// Delete removes a template
func (s *TemplateStore) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.templates[id]; !ok {
		return false
	}
	delete(s.templates, id)
	return true
}

// Global template store
var templateStore = NewTemplateStore()

// TemplateWithMetadata adds metadata to templates
type TemplateWithMetadata struct {
	models.EventTemplate
	Source    string    `json:"source"` // "builtin" or "custom"
	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// ListTemplates returns all templates (builtin + custom)
func ListTemplates(c *gin.Context) {
	category := c.Query("category")

	templates := make([]TemplateWithMetadata, 0)

	// Add builtin templates from generators
	for _, gen := range generators.Registry {
		for _, tmpl := range gen.GetTemplates() {
			if category != "" && tmpl.Category != category {
				continue
			}
			templates = append(templates, TemplateWithMetadata{
				EventTemplate: tmpl,
				Source:        "builtin",
			})
		}
	}

	// Add custom templates
	for _, tmpl := range templateStore.List() {
		if category != "" && tmpl.Category != category {
			continue
		}
		templates = append(templates, TemplateWithMetadata{
			EventTemplate: *tmpl,
			Source:        "custom",
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"templates": templates,
		"count":     len(templates),
	})
}

// GetTemplate returns a specific template
func GetTemplate(c *gin.Context) {
	id := c.Param("id")

	// Check custom templates first
	if tmpl, ok := templateStore.Get(id); ok {
		c.JSON(http.StatusOK, TemplateWithMetadata{
			EventTemplate: *tmpl,
			Source:        "custom",
		})
		return
	}

	// Check builtin templates
	for _, gen := range generators.Registry {
		for _, tmpl := range gen.GetTemplates() {
			if tmpl.ID == id {
				c.JSON(http.StatusOK, TemplateWithMetadata{
					EventTemplate: tmpl,
					Source:        "builtin",
				})
				return
			}
		}
	}

	c.JSON(http.StatusNotFound, gin.H{
		"error": "Template not found",
	})
}

// CreateTemplate creates a new custom template
func CreateTemplate(c *gin.Context) {
	var tmpl models.EventTemplate
	if err := c.ShouldBindJSON(&tmpl); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	tmpl.ID = "custom-" + uuid.New().String()

	templateStore.Create(&tmpl)

	c.JSON(http.StatusCreated, TemplateWithMetadata{
		EventTemplate: tmpl,
		Source:        "custom",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	})
}

// UpdateTemplate updates an existing custom template
func UpdateTemplate(c *gin.Context) {
	id := c.Param("id")

	// Check if it's a builtin template
	for _, gen := range generators.Registry {
		for _, tmpl := range gen.GetTemplates() {
			if tmpl.ID == id {
				c.JSON(http.StatusForbidden, gin.H{
					"error": "Cannot modify builtin templates",
				})
				return
			}
		}
	}

	if _, ok := templateStore.Get(id); !ok {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Template not found",
		})
		return
	}

	var tmpl models.EventTemplate
	if err := c.ShouldBindJSON(&tmpl); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	tmpl.ID = id
	templateStore.Update(&tmpl)

	c.JSON(http.StatusOK, TemplateWithMetadata{
		EventTemplate: tmpl,
		Source:        "custom",
		UpdatedAt:     time.Now(),
	})
}

// DeleteTemplate removes a custom template
func DeleteTemplate(c *gin.Context) {
	id := c.Param("id")

	// Check if it's a builtin template
	for _, gen := range generators.Registry {
		for _, tmpl := range gen.GetTemplates() {
			if tmpl.ID == id {
				c.JSON(http.StatusForbidden, gin.H{
					"error": "Cannot delete builtin templates",
				})
				return
			}
		}
	}

	if !templateStore.Delete(id) {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Template not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Template deleted",
	})
}
