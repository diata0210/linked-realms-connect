package main

import (
	"os"
	"path/filepath"
	"testing"
)

func fixtureFiles() []string {
	names := append(append([]string{}, files...), "protocol/manifest.json")
	if _, err := os.Stat("../../protocol/vectors/nk-transcript.json"); err == nil {
		names = append(names, "protocol/vectors/nk-transcript.json")
	}
	return names
}
func TestAdditiveTranscriptPin(t *testing.T) {
	root := copySpecFixture(t)
	path := filepath.Join(root, "protocol/vectors/nk-transcript.json")
	if err := run(root, false); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, append(b, ' '), 0644); err != nil {
		t.Fatal(err)
	}
	if run(root, false) == nil {
		t.Fatal("mutated transcript accepted")
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if run(root, false) == nil {
		t.Fatal("missing transcript accepted")
	}
}
