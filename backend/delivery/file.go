package delivery

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"siem-event-generator/models"
)

// FileSender writes events to a file
type FileSender struct {
	file   *os.File
	config models.DestinationConfig
	mu     sync.Mutex
}

// NewFileSender creates a new file sender
func NewFileSender(config models.DestinationConfig) (*FileSender, error) {
	if config.FilePath == "" {
		return nil, fmt.Errorf("file path is required")
	}

	// Ensure directory exists
	dir := filepath.Dir(config.FilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	// Open file for appending
	file, err := os.OpenFile(config.FilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	return &FileSender{
		file:   file,
		config: config,
	}, nil
}

// Send writes an event to the file
func (f *FileSender) Send(event *models.GeneratedEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Check file size and rotate if needed
	if err := f.checkRotate(); err != nil {
		return err
	}

	// Write the raw event with a newline
	_, err := f.file.WriteString(event.RawEvent + "\n")
	if err != nil {
		return fmt.Errorf("failed to write event: %w", err)
	}

	return nil
}

// checkRotate checks if file rotation is needed
func (f *FileSender) checkRotate() error {
	if f.config.MaxSizeMB <= 0 {
		return nil
	}

	info, err := f.file.Stat()
	if err != nil {
		return err
	}

	maxBytes := int64(f.config.MaxSizeMB) * 1024 * 1024
	if info.Size() < maxBytes {
		return nil
	}

	// Close current file
	f.file.Close()

	// Rotate existing files
	if err := f.rotateFiles(); err != nil {
		return err
	}

	// Open new file
	file, err := os.OpenFile(f.config.FilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open new file: %w", err)
	}

	f.file = file
	return nil
}

// rotateFiles rotates log files (file.log -> file.log.1, etc.)
func (f *FileSender) rotateFiles() error {
	keep := f.config.RotateKeep
	if keep <= 0 {
		keep = 5
	}

	// Remove oldest file if it exists
	oldestFile := fmt.Sprintf("%s.%d", f.config.FilePath, keep)
	os.Remove(oldestFile)

	// Rotate files
	for i := keep - 1; i >= 1; i-- {
		oldName := fmt.Sprintf("%s.%d", f.config.FilePath, i)
		newName := fmt.Sprintf("%s.%d", f.config.FilePath, i+1)

		if _, err := os.Stat(oldName); err == nil {
			os.Rename(oldName, newName)
		}
	}

	// Rename current file to .1
	if _, err := os.Stat(f.config.FilePath); err == nil {
		os.Rename(f.config.FilePath, f.config.FilePath+".1")
	}

	return nil
}

// Test tests the file destination
func (f *FileSender) Test() error {
	// Try to write to the file
	f.mu.Lock()
	defer f.mu.Unlock()

	_, err := f.file.WriteString("# Connection test\n")
	if err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}

	return f.file.Sync()
}

// Close closes the file
func (f *FileSender) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.file != nil {
		return f.file.Close()
	}
	return nil
}
