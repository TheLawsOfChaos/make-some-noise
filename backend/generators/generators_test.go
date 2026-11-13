package generators

import (
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"
)

// Every template of every registered generator must produce a single-line
// event that parses as what its format claims, with a sourcetype set.
func TestEveryTemplateGeneratesValidSingleLineEvent(t *testing.T) {
	if len(Registry) == 0 {
		t.Fatal("no generators registered")
	}
	for id, gen := range Registry {
		templates := gen.GetTemplates()
		if len(templates) == 0 {
			t.Errorf("%s: no templates", id)
		}
		for _, tmpl := range templates {
			ev, err := gen.Generate(tmpl.ID, nil)
			if err != nil {
				t.Errorf("%s/%s: %v", id, tmpl.ID, err)
				continue
			}
			if ev.RawEvent == "" {
				t.Errorf("%s/%s: empty raw event", id, tmpl.ID)
			}
			if strings.Contains(ev.RawEvent, "\n") {
				t.Errorf("%s/%s: raw event spans several lines", id, tmpl.ID)
			}
			if ev.Sourcetype == "" {
				t.Errorf("%s/%s: no sourcetype", id, tmpl.ID)
			}
			if ev.Timestamp.IsZero() {
				t.Errorf("%s/%s: zero timestamp", id, tmpl.ID)
			}
			switch tmpl.Format {
			case "json":
				if !json.Valid([]byte(ev.RawEvent)) {
					t.Errorf("%s/%s: raw event is not valid JSON: %.80s", id, tmpl.ID, ev.RawEvent)
				}
			case "xml":
				var v struct{}
				if err := xml.Unmarshal([]byte(ev.RawEvent), &v); err != nil {
					t.Errorf("%s/%s: raw event is not valid XML: %v", id, tmpl.ID, err)
				}
			}
		}
	}
}

func TestRandomHexIsHex(t *testing.T) {
	b := &BaseGenerator{}
	h := b.RandomHex(64)
	if len(h) != 64 || strings.Trim(h, "0123456789abcdef") != "" {
		t.Fatalf("not 64 hex chars: %q", h)
	}
}

func TestUnknownTemplateFails(t *testing.T) {
	for id, gen := range Registry {
		if _, err := gen.Generate("no-such-template", nil); err == nil {
			t.Errorf("%s: unknown template did not fail", id)
		}
	}
}
