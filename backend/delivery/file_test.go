package delivery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"siem-event-generator/models"
)

func TestFileSenderStaysInsideOutputRoot(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OUTPUT_DIR", root)

	outside := t.TempDir()
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Skip("symlinks not supported")
	}

	bad := []string{
		"/etc/passwd",
		filepath.Join(root, "..", "x.log"),
		filepath.Join(root, "escape", "x.log"),
		"relative.log",
	}
	for _, p := range bad {
		if _, err := NewFileSender(models.DestinationConfig{FilePath: p}); err == nil {
			t.Errorf("%s: accepted a path outside the output root", p)
		}
	}

	good := filepath.Join(root, "sub", "events.log")
	f, err := NewFileSender(models.DestinationConfig{FilePath: good})
	if err != nil {
		t.Fatal(err)
	}
	ev := &models.GeneratedEvent{RawEvent: `{"a":1}`, Timestamp: time.Now()}
	f.Send(ev)
	f.Send(ev)
	f.Close()
	data, _ := os.ReadFile(good)
	if lines := strings.Split(strings.TrimSpace(string(data)), "\n"); len(lines) != 2 || lines[0] != `{"a":1}` {
		t.Fatalf("expected one event per line, got %q", data)
	}
}
