package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixtureRow(t *testing.T, v map[string]any, category, name string) map[string]any {
	t.Helper()
	for _, value := range v[category].([]any) {
		row := value.(map[string]any)
		if row["name"] == name {
			return row
		}
	}
	t.Fatalf("missing fixture %s/%s", category, name)
	return nil
}

// Keep both representations consistent so semantic tests reach the cursor/hash
// checks instead of failing only because the duplicated body differs.
func replaceFixtureBody(t *testing.T, row map[string]any, body []byte) {
	t.Helper()
	envelope, err := hex.DecodeString(row["envelope_hex"].(string))
	if err != nil {
		t.Fatal(err)
	}
	header := append([]byte{}, envelope[:140]...)
	binary.BigEndian.PutUint32(header[136:140], uint32(len(body)))
	updated := append(header, body...)
	updated = append(updated, envelope[len(envelope)-64:]...)
	row["body_hex"] = hex.EncodeToString(body)
	row["envelope_hex"] = hex.EncodeToString(updated)
}

func copySpecFixture(t *testing.T) string {
	t.Helper()
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
	return root
}

func writeFixtureVectors(t *testing.T, root string, v map[string]any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "protocol", "vectors", "v1.json"), b, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestRequiredVectorDataCannotRepin(t *testing.T) {
	mutations := map[string]func(*testing.T, map[string]any){
		"frames replaced by placeholder": func(t *testing.T, v map[string]any) {
			v["frames"] = []any{map[string]any{"name": "placeholder-frame", "expect": "accept"}}
		},
		"known answers names only": func(t *testing.T, v map[string]any) {
			for i, value := range v["known_answer"].([]any) {
				v["known_answer"].([]any)[i] = map[string]any{"name": value.(map[string]any)["name"]}
			}
		},
		"quest body and envelope 00": func(t *testing.T, v map[string]any) {
			for _, value := range v["quest_pagination"].([]any) {
				row := value.(map[string]any)
				row["body_hex"], row["envelope_hex"] = "00", "00"
			}
		},
		"cursor body missing poster": func(t *testing.T, v map[string]any) {
			row := fixtureRow(t, v, "quest_pagination", "quest_query_cursor_present")
			body, _ := hex.DecodeString(row["body_hex"].(string))
			replaceFixtureBody(t, row, append(body[:17:17], body[49:]...))
		},
		"cursor metadata missing poster": func(t *testing.T, v map[string]any) {
			row := fixtureRow(t, v, "quest_pagination", "quest_query_cursor_present")
			delete(row["cursor"].(map[string]any), "poster_key_hex")
		},
		"page next missing poster": func(t *testing.T, v map[string]any) {
			row := fixtureRow(t, v, "quest_pagination", "quest_page_shared_id_order")
			body, _ := hex.DecodeString(row["body_hex"].(string))
			replaceFixtureBody(t, row, append(body[:73:73], body[105:]...))
		},
		"quest tuple metadata reversed": func(t *testing.T, v map[string]any) {
			row := fixtureRow(t, v, "quest_pagination", "quest_page_shared_id_order")
			tuples := row["ordered_tuples_hex"].([]any)
			tuples[0], tuples[1] = tuples[1], tuples[0]
		},
		"ACK request hash zero": func(t *testing.T, v map[string]any) {
			row := fixtureRow(t, v, "envelopes", "signed_kind_08")
			body, _ := hex.DecodeString(row["body_hex"].(string))
			clear(body[:32])
			replaceFixtureBody(t, row, body)
		},
		"HEARTBEAT changed after ACK": func(t *testing.T, v map[string]any) {
			row := fixtureRow(t, v, "envelopes", "signed_kind_12")
			envelope, _ := hex.DecodeString(row["envelope_hex"].(string))
			envelope[len(envelope)-1] ^= 1
			row["envelope_hex"] = hex.EncodeToString(envelope)
		},
	}
	for _, category := range []string{"wallet", "known_answer", "derivations", "negative", "quest_pagination", "frames"} {
		for _, value := range vectorObject(t)[category].([]any) {
			row := value.(map[string]any)
			name := row["name"].(string)
			add := func(label string, mutate func(map[string]any)) {
				mutations[category+"/"+name+"/"+label] = func(t *testing.T, v map[string]any) {
					mutate(fixtureRow(t, v, category, name))
				}
			}
			switch category {
			case "frames":
				for _, field := range []string{"frame_hex", "next_sequence", "associated_data_hex"} {
					if _, ok := row[field]; !ok {
						continue
					}
					for _, bad := range []any{nil, "", "0", "zz", "00", 123} {
						if bad == row[field] {
							continue
						}
						add(field+"="+fmtValue(bad), func(r map[string]any) { r[field] = bad })
					}
				}
				add("zero frame", func(r map[string]any) { r["frame_hex"] = strings.Repeat("0", len(r["frame_hex"].(string))) })
				add("wrong expectation", func(r map[string]any) {
					if r["expect"] == "reject" {
						r["expect"] = "accept"
						delete(r, "error")
					} else {
						r["expect"] = "reject"
						r["error"] = map[string]any{"code": 1, "name": "MALFORMED"}
					}
				})
			case "wallet":
				for _, bad := range []any{"", "0", "zz", "00", 123} {
					add("bad envelope "+fmtValue(bad), func(r map[string]any) { r["envelope_hex"] = bad })
				}
			case "known_answer", "derivations":
				for _, field := range []string{"private_hex", "chain_code_hex", "public_hex"} {
					original, ok := row[field].(string)
					if !ok {
						continue // Published leading-zero case has no public_hex.
					}
					for _, bad := range []any{nil, 123, "zz", "00", strings.Repeat("0", len(original))} {
						add(field+"="+fmtValue(bad), func(r map[string]any) { r[field] = bad })
					}
				}
				if category == "known_answer" {
					for _, field := range []string{"seed_hex", "path"} {
						for _, bad := range []any{nil, 123, "", "00"} {
							add(field+"="+fmtValue(bad), func(r map[string]any) { r[field] = bad })
						}
					}
				}
			case "negative":
				if row["expect"] == "reject" {
					add("flipped to accept", func(r map[string]any) { r["expect"] = "accept"; delete(r, "error") })
				}
			case "quest_pagination":
				add("body 00", func(r map[string]any) { replaceFixtureBody(t, r, []byte{0}) })
				add("body envelope mismatch", func(r map[string]any) { r["body_hex"] = "000001" })
			}
		}
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			root := copySpecFixture(t)
			if _, err := content(root); err != nil {
				t.Fatalf("baseline invalid: %v", err)
			}
			v := vectorObject(t)
			mutate(t, v)
			writeFixtureVectors(t, root, v)
			manifestPath := filepath.Join(root, "protocol", "manifest.json")
			before, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			for _, write := range []bool{false, true} {
				if err := run(root, write); err == nil || strings.Contains(err.Error(), "SHA-256 mismatch") {
					t.Fatalf("write=%v: must reject vector data before hashes: %v", write, err)
				}
			}
			after, err := os.ReadFile(manifestPath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("rejected data changed manifest: %v", err)
			}
		})
	}
}

func fmtValue(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestRepinRereadsAndValidates(t *testing.T) {
	for _, mutation := range []string{"invalid vectors", "valid changed vectors", "valid changed spec", "unchanged"} {
		t.Run(mutation, func(t *testing.T) {
			root := copySpecFixture(t)
			validated, err := content(root)
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(filepath.Join(root, "protocol", "manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			if mutation == "valid changed spec" {
				if err := os.WriteFile(filepath.Join(root, "protocol", "v1.md"), append(specBytes(t), '\n'), 0644); err != nil {
					t.Fatal(err)
				}
			} else if mutation != "unchanged" {
				v := vectorObject(t)
				if mutation == "invalid vectors" {
					fixtureRow(t, v, "wallet", "absent")["envelope_hex"] = ""
				} else {
					v["notice"] = "Changed after validation"
				}
				writeFixtureVectors(t, root, v)
			}
			err = writeManifest(root, validated)
			if (err != nil) != (mutation != "unchanged") {
				t.Fatalf("unexpected repin result: %v", err)
			}
			if mutation == "invalid vectors" && strings.Contains(err.Error(), "content changed") {
				t.Fatal("must revalidate data, not only compare hashes")
			}
			after, readErr := os.ReadFile(filepath.Join(root, "protocol", "manifest.json"))
			if readErr != nil || (mutation != "unchanged" && !bytes.Equal(before, after)) {
				t.Fatalf("failed repin changed manifest: %v", readErr)
			}
			if mutation == "unchanged" {
				if err := run(root, false); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
