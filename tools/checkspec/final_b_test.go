package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManifestRejectsCaseAliases(t *testing.T) {
	want, err := content("../..")
	if err != nil {
		t.Fatal(err)
	}
	hashes, err := json.Marshal(want.Files)
	if err != nil {
		t.Fatal(err)
	}
	wrong := map[string]string{}
	for name := range want.Files {
		wrong[name] = strings.Repeat("0", 64)
	}
	wrongHashes, err := json.Marshal(wrong)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		"version override":       fmt.Sprintf(`{"protocol_version":2,"Protocol_Version":1,"files":%s}`, hashes),
		"hash override":          fmt.Sprintf(`{"protocol_version":1,"files":%s,"Files":%s}`, wrongHashes, hashes),
		"renamed version":        fmt.Sprintf(`{"Protocol_Version":1,"files":%s}`, hashes),
		"renamed files":          fmt.Sprintf(`{"protocol_version":1,"Files":%s}`, hashes),
		"alias before canonical": fmt.Sprintf(`{"Protocol_Version":2,"protocol_version":1,"files":%s}`, hashes),
	} {
		t.Run(name, func(t *testing.T) {
			root := copySpecFixture(t)
			if err := os.WriteFile(filepath.Join(root, "protocol", "manifest.json"), []byte(data), 0644); err != nil {
				t.Fatal(err)
			}
			if err := run(root, false); err == nil {
				t.Fatal("accepted case alias in manifest")
			}
		})
	}
}

func assertContentCannotRepin(t *testing.T, root string) {
	t.Helper()
	path := filepath.Join(root, "protocol", "manifest.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, write := range []bool{false, true} {
		if err := run(root, write); err == nil || strings.Contains(err.Error(), "SHA-256 mismatch") {
			t.Errorf("write=%v: must reject content independently of hashes: %v", write, err)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("rejected content changed manifest")
	}
}

func TestHumanTableRejectsUnparsedRows(t *testing.T) {
	for _, tc := range []struct{ name, table, row string }{
		{"compact extra kind", "kinds", "|33|UNLISTED| Empty |"},
		{"compact duplicate error", "errors", "|1|ALIEN|"},
		{"negative op", "ops", "| -1 | NEGATIVE | Empty |"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := copySpecFixture(t)
			marker := "<!-- /" + tc.table + " -->"
			original := string(specBytes(t))
			if strings.Count(original, marker) != 1 {
				t.Fatal("mutation target absent or duplicated")
			}
			changed := strings.Replace(original, marker, tc.row+"\n"+marker, 1)
			if err := os.WriteFile(filepath.Join(root, "protocol", "v1.md"), []byte(changed), 0644); err != nil {
				t.Fatal(err)
			}
			assertContentCannotRepin(t, root)
		})
	}
}

func TestNonCanonicalFileBytesCannotRepin(t *testing.T) {
	for _, name := range files {
		for _, format := range []string{"CRLF", "BOM"} {
			t.Run(name+"/"+format, func(t *testing.T) {
				root := copySpecFixture(t)
				path := filepath.Join(root, filepath.FromSlash(name))
				original, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				changed := bytes.ReplaceAll(original, []byte("\n"), []byte("\r\n"))
				if format == "BOM" {
					changed = append([]byte{0xef, 0xbb, 0xbf}, original...)
				}
				if bytes.Equal(original, changed) {
					t.Fatal("mutation did not change bytes")
				}
				if err := os.WriteFile(path, changed, 0644); err != nil {
					t.Fatal(err)
				}
				assertContentCannotRepin(t, root)
			})
		}
	}
}
