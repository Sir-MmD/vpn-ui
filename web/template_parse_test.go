package web

import (
	"html/template"
	"testing"
)

// TestEditedTemplatesParse guards the Go-template syntax of the HTML templates that
// carry the multi-select / bulk-ops / export UI. getHtmlTemplate() silently ignores
// ParseFS errors, so a broken template would only surface as a runtime 500 — this
// catches it at test time instead. Vue expressions use [[ ]] delimiters, so the only
// Go-template function the parser needs defined is i18n.
func TestEditedTemplatesParse(t *testing.T) {
	funcMap := template.FuncMap{
		"i18n": func(key string, args ...string) (string, error) { return "", nil },
	}
	files := []string{
		"html/inbounds.html",
		"html/component/aClientTable.html",
		"html/index.html", // dashboard incl. the unsupported-distro warning modal
	}
	for _, f := range files {
		b, err := htmlFS.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if _, err := template.New(f).Funcs(funcMap).Parse(string(b)); err != nil {
			t.Errorf("%s failed to parse: %v", f, err)
		}
	}
}
