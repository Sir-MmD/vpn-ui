package web

import (
	"io/fs"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// TestTranslationsAreValidToml unmarshals every embedded translation file so a
// malformed key (e.g. a bad bulk-ops i18n insertion) fails here instead of silently
// breaking i18n at runtime.
func TestTranslationsAreValidToml(t *testing.T) {
	entries, err := fs.ReadDir(i18nFS, "translation")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := i18nFS.ReadFile("translation/" + e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		var m map[string]any
		if err := toml.Unmarshal(data, &m); err != nil {
			t.Errorf("%s: invalid TOML: %v", e.Name(), err)
		}
	}
}
