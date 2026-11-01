package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFrozenSpec(t *testing.T) {
	if err := run("../..", false); err != nil {
		t.Fatal(err)
	}
}

func specBytes(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../../protocol/v1.md")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTableMutations(t *testing.T) {
	original := string(specBytes(t))
	for _, tc := range []struct{ name, old, new string }{
		{"duplicate human code", "| 2 | INFO |", "| 1 | INFO |"},
		{"hole human op", "| 12 | STREAM_CLOSE |", "| 13 | STREAM_CLOSE |"},
		{"wrong human name", "| 3 | BAD_SIGNATURE |", "| 3 | FORGED |"},
		{"duplicate machine code", `[2,"INFO"]`, `[1,"INFO"]`},
		{"duplicate machine name", `[2,"INFO"]`, `[2,"INFO_REQUEST"]`},
		{"wrong machine name", `[12,"STREAM_CLOSE"]`, `[12,"CLOSED"]`},
		{"error start", `[0,"orderly close"]`, `[1,"orderly close"]`},
		{"duplicate marker", "<!-- ops -->", "<!-- ops --><!-- ops -->"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(original, tc.old) {
				t.Fatal("mutation target absent")
			}
			if _, err := parseTables([]byte(strings.Replace(original, tc.old, tc.new, 1))); err == nil {
				t.Fatal("accepted broken table")
			}
		})
	}
}

func TestAllReferencesAndMutations(t *testing.T) {
	tables, err := parseTables(specBytes(t))
	if err != nil {
		t.Fatal(err)
	}
	for singular, plural := range map[string]string{"kind": "kinds", "op": "ops", "error": "errors"} {
		for _, row := range tables[plural] {
			for _, bad := range []string{"", "code", "name", "shape"} {
				r := map[string]any{"code": row.Code, "name": row.Name}
				var ref any = r
				switch bad {
				case "code":
					r["code"] = 999
				case "name":
					r["name"] = "unknown"
				case "shape":
					ref = row.Code
				}
				v := vectorObject(t)
				v["nested"] = []any{map[string]any{singular: ref}}
				b, err := json.Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
				err = validateVectors(b, tables)
				if (err != nil) != (bad != "") {
					t.Fatalf("%s %d mutation=%s: %v", singular, row.Code, bad, err)
				}
			}
		}
	}
}

func vectorObject(t *testing.T) map[string]any {
	t.Helper()
	b, err := os.ReadFile("../../protocol/vectors/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	v, err := strictJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

func TestRequiredVectorCoverage(t *testing.T) {
	tables, err := parseTables(specBytes(t))
	if err != nil {
		t.Fatal(err)
	}
	validate := func(t *testing.T, v map[string]any) {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateVectors(b, tables); err == nil {
			t.Fatal("accepted incomplete vector coverage")
		}
	}
	for _, category := range []string{"envelopes", "operations", "derivations", "known_answer", "key_files", "wallet", "negative", "time", "objects", "frames", "quest_pagination", "prologue"} {
		t.Run("missing category/"+category, func(t *testing.T) {
			v := vectorObject(t)
			delete(v, category)
			validate(t, v)
		})
		if category == "prologue" {
			continue
		}
		t.Run("empty category/"+category, func(t *testing.T) {
			v := vectorObject(t)
			v[category] = []any{}
			validate(t, v)
		})
	}
	for _, category := range []string{"envelopes", "operations", "derivations", "known_answer", "key_files", "wallet", "negative", "time", "quest_pagination"} {
		for i, value := range vectorObject(t)[category].([]any) {
			name := value.(map[string]any)["name"].(string)
			t.Run("missing case/"+name, func(t *testing.T) {
				v := vectorObject(t)
				rows := v[category].([]any)
				v[category] = append(rows[:i], rows[i+1:]...)
				validate(t, v)
			})
		}
	}
	for _, mutation := range []string{"duplicate name", "duplicate name across categories", "empty name", "two seeds", "duplicate seed/profile", "wrong signed kind", "wallet wrong error", "quest wrong kind", "quest missing bytes", "quest rejected"} {
		t.Run(mutation, func(t *testing.T) {
			v := vectorObject(t)
			rows := v["envelopes"].([]any)
			switch mutation {
			case "duplicate name":
				v["envelopes"] = append(rows, rows[0])
			case "duplicate name across categories":
				v["objects"].([]any)[0].(map[string]any)["name"] = rows[0].(map[string]any)["name"]
			case "empty name":
				rows[0].(map[string]any)["name"] = ""
			case "two seeds":
				v["derivations"] = v["derivations"].([]any)[:6]
			case "duplicate seed/profile":
				rows = v["derivations"].([]any)
				rows[1].(map[string]any)["profile"] = rows[0].(map[string]any)["profile"]
			case "wrong signed kind":
				rows[0].(map[string]any)["kind"] = rows[1].(map[string]any)["kind"]
			case "wallet wrong error":
				rows = v["wallet"].([]any)
				rows[len(rows)-1].(map[string]any)["error"] = map[string]any{"code": 1, "name": "MALFORMED"}
			case "quest wrong kind":
				v["quest_pagination"].([]any)[0].(map[string]any)["kind"] = map[string]any{"code": 3, "name": "DIRECTORY_QUERY"}
			case "quest missing bytes":
				delete(v["quest_pagination"].([]any)[1].(map[string]any), "body_hex")
			case "quest rejected":
				row := v["quest_pagination"].([]any)[2].(map[string]any)
				row["expect"] = "reject"
				row["error"] = map[string]any{"code": 1, "name": "MALFORMED"}
			}
			validate(t, v)
		})
	}
}

func TestInvalidVectorsCannotRepin(t *testing.T) {
	for _, mutation := range []string{"empty file", "version only", "empty arrays", "65_rejected", "altered_address_breaks_signature", "missing quest cursor", "missing shared quest ID page"} {
		t.Run(mutation, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "protocol", "vectors"), 0755); err != nil {
				t.Fatal(err)
			}
			for _, name := range fixtureFiles() {
				b, err := os.ReadFile(filepath.Join("../..", name))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, name), b, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if err := run(root, false); err != nil {
				t.Fatal(err)
			}
			v := vectorObject(t)
			switch mutation {
			case "empty file", "version only":
				v = map[string]any{"protocol_version": 1}
			case "empty arrays":
				for key, value := range v {
					if _, ok := value.([]any); ok {
						v[key] = []any{}
					}
				}
			case "missing quest cursor", "missing shared quest ID page":
				name := "quest_query_cursor_present"
				if mutation == "missing shared quest ID page" {
					name = "quest_page_shared_id_order"
				}
				rows := v["quest_pagination"].([]any)
				for i, value := range rows {
					if value.(map[string]any)["name"] == name {
						v["quest_pagination"] = append(rows[:i], rows[i+1:]...)
						break
					}
				}
			default:
				for _, value := range v["wallet"].([]any) {
					row := value.(map[string]any)
					if row["name"] == mutation {
						row["expect"] = "accept"
						delete(row, "error")
					}
				}
			}
			b, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			if mutation == "empty file" {
				b = nil
			}
			if err := os.WriteFile(filepath.Join(root, "protocol", "vectors", "v1.json"), b, 0644); err != nil {
				t.Fatal(err)
			}
			manifestPath := filepath.Join(root, "protocol", "manifest.json")
			before, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			for _, write := range []bool{false, true} {
				err := run(root, write)
				if err == nil || strings.Contains(err.Error(), "SHA-256 mismatch") {
					t.Fatalf("write=%v: must reject content independently of hashes: %v", write, err)
				}
			}
			after, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("failed validation changed manifest")
			}
		})
	}
}

func TestStrictJSON(t *testing.T) {
	if _, err := strictJSON([]byte{'"', 0xff, '"'}); err == nil {
		t.Fatal("accepted invalid UTF-8 JSON")
	}
	for _, input := range []string{`{"x":1,"x":2}`, `{"a":{"x":1,"x":2}}`, `{} {}`, `[1,]`, `{"x":`} {
		if _, err := strictJSON([]byte(input)); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
}

func TestManifestMutations(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "protocol", "vectors"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range fixtureFiles() {
		b, err := os.ReadFile(filepath.Join("../..", name))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(tmp, name), b, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := run(tmp, false); err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		path := filepath.Join(tmp, name)
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, append(append([]byte{}, original...), '\n'), 0644); err != nil {
			t.Fatal(err)
		}
		if err = run(tmp, false); err == nil {
			t.Fatalf("ignored changed hash %s", name)
		}
		if err = os.WriteFile(path, original, 0644); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(tmp, "protocol", "manifest.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err = json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"extra file", "extra field", "version"} {
		var copyM map[string]any
		if err = json.Unmarshal(b, &copyM); err != nil {
			t.Fatal(err)
		}
		switch mutation {
		case "extra file":
			copyM["files"].(map[string]any)["protocol/agent-release.json"] = strings.Repeat("0", 64)
		case "extra field":
			copyM["client_build"] = "not allowed"
		case "version":
			copyM["protocol_version"] = 2
		}
		changed, err := json.Marshal(copyM)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, changed, 0644); err != nil {
			t.Fatal(err)
		}
		if err = run(tmp, false); err == nil {
			t.Fatal("accepted " + mutation)
		}
	}
}
