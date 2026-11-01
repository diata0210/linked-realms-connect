// checkspec verifies the frozen documents without importing protocol or crypto libraries.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

type entry struct {
	Code int
	Name string
}
type manifest struct {
	ProtocolVersion int               `json:"protocol_version"`
	Files           map[string]string `json:"files"`
}

var files = []string{"protocol/v1.md", "protocol/vectors/v1.json"}
var ranges = map[string][2]int{"kinds": {1, 32}, "ops": {1, 12}, "errors": {0, 17}}

// Reject duplicate JSON keys at any depth, which encoding/json alone accepts.
func strictJSON(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("invalid UTF-8 JSON")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var read func() (any, error)
	read = func() (any, error) {
		t, err := d.Token()
		if err != nil {
			return nil, err
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return t, nil
		}
		switch delim {
		case '{':
			m := map[string]any{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return nil, err
				}
				name, ok := k.(string)
				if !ok {
					return nil, errors.New("nonstring object key")
				}
				if _, ok = m[name]; ok {
					return nil, fmt.Errorf("duplicate JSON key %s", name)
				}
				v, err := read()
				if err != nil {
					return nil, err
				}
				m[name] = v
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, errors.New("unterminated object")
			}
			return m, nil
		case '[':
			var a []any
			for d.More() {
				v, err := read()
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, errors.New("unterminated array")
			}
			return a, nil
		default:
			return nil, errors.New("unexpected delimiter")
		}
	}
	v, err := read()
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	return v, nil
}

func section(doc, tag string) (string, error) {
	start, end := "<!-- "+tag+" -->", "<!-- /"+tag+" -->"
	if strings.Count(doc, start) != 1 || strings.Count(doc, end) != 1 {
		return "", fmt.Errorf("missing/duplicate %s markers", tag)
	}
	part := strings.SplitN(doc, start, 2)[1]
	if !strings.Contains(part, end) {
		return "", fmt.Errorf("reversed %s markers", tag)
	}
	return strings.SplitN(part, end, 2)[0], nil
}

func number(v any) (int, error) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, errors.New("code must be integer")
	}
	i, err := strconv.Atoi(string(n))
	return i, err
}

func validateTable(rows []entry, start, count int) error {
	if len(rows) != count {
		return fmt.Errorf("table has %d entries, expected %d", len(rows), count)
	}
	names := map[string]bool{}
	for i, r := range rows {
		if r.Code != start+i {
			return fmt.Errorf("noncontiguous/duplicate code %d at %d", r.Code, i)
		}
		if r.Name == "" || names[r.Name] {
			return fmt.Errorf("empty/duplicate name %q", r.Name)
		}
		names[r.Name] = true
	}
	return nil
}

func parseTables(doc []byte) (map[string][]entry, error) {
	block, err := section(string(doc), "code-table")
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile("(?s)^\\s*```json\\s+(.*?)\\s*```\\s*$")
	match := re.FindStringSubmatch(block)
	if match == nil {
		return nil, errors.New("machine table must be one JSON fence")
	}
	v, err := strictJSON([]byte(match[1]))
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok || len(m) != 3 {
		return nil, errors.New("expected exactly kinds/ops/errors")
	}
	out := map[string][]entry{}
	rowRE := regexp.MustCompile(`(?m)^\| ([0-9]+) \| ([^|]+?) \|[^\r\n]*\|\r?$`)
	for name, bounds := range ranges {
		rows, ok := m[name].([]any)
		if !ok {
			return nil, fmt.Errorf("missing array %s", name)
		}
		for _, r := range rows {
			pair, ok := r.([]any)
			if !ok || len(pair) != 2 {
				return nil, errors.New("invalid machine row")
			}
			code, err := number(pair[0])
			if err != nil {
				return nil, err
			}
			s, ok := pair[1].(string)
			if !ok {
				return nil, errors.New("nonstring name")
			}
			out[name] = append(out[name], entry{code, s})
		}
		if err = validateTable(out[name], bounds[0], bounds[1]); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		prose, err := section(string(doc), name)
		if err != nil {
			return nil, err
		}
		var visible []entry
		header := "| Code | Name | Body |"
		if name == "errors" {
			header = "| Code | Name | Meaning |"
		}
		for _, line := range strings.Split(prose, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || line == header || line == "| --- | --- | --- |" {
				continue
			}
			r := rowRE.FindStringSubmatch(line)
			if r == nil {
				return nil, fmt.Errorf("human %s: unparsed table row %q", name, line)
			}
			code, err := strconv.Atoi(r[1])
			if err != nil {
				return nil, err
			}
			visible = append(visible, entry{code, strings.TrimSpace(r[2])})
		}
		if err = validateTable(visible, bounds[0], bounds[1]); err != nil {
			return nil, fmt.Errorf("human %s: %w", name, err)
		}
		if !reflect.DeepEqual(visible, out[name]) {
			return nil, fmt.Errorf("human/machine %s differ", name)
		}
	}
	return out, nil
}

func validateVectors(data []byte, tables map[string][]entry) error {
	v, err := strictJSON(data)
	if err != nil {
		return err
	}
	top, ok := v.(map[string]any)
	if !ok {
		return errors.New("vectors must be object")
	}
	version, err := number(top["protocol_version"])
	if err != nil || version != 1 {
		return errors.New("vector version must be 1")
	}
	lookup := map[string]map[int]string{}
	for singular, plural := range map[string]string{"kind": "kinds", "op": "ops", "error": "errors"} {
		lookup[singular] = map[int]string{}
		for _, r := range tables[plural] {
			lookup[singular][r.Code] = r.Name
		}
	}
	var walk func(any, string) error
	walk = func(v any, path string) error {
		switch x := v.(type) {
		case map[string]any:
			for k, value := range x {
				if names, reference := lookup[k]; reference {
					r, ok := value.(map[string]any)
					if !ok || len(r) != 2 {
						return fmt.Errorf("%s.%s: reference needs code/name", path, k)
					}
					code, err := number(r["code"])
					name, ok := r["name"].(string)
					expected, exists := names[code]
					if err != nil || !ok || !exists || name != expected {
						return fmt.Errorf("%s.%s: unknown/mismatched reference", path, k)
					}
				} else if err := walk(value, path+"."+k); err != nil {
					return err
				}
			}
		case []any:
			for i, value := range x {
				if err := walk(value, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(v, "vectors"); err != nil {
		return err
	}
	return validateCoverage(top)
}

func content(root string) (manifest, error) {
	var data [2][]byte
	var err error
	m := manifest{1, map[string]string{}}
	for i, name := range files {
		data[i], err = os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			return m, err
		}
		if bytes.ContainsRune(data[i], '\r') || bytes.HasPrefix(data[i], []byte{0xef, 0xbb, 0xbf}) {
			return m, fmt.Errorf("%s: expected LF with no BOM", name)
		}
		m.Files[name] = fmt.Sprintf("%x", sha256.Sum256(data[i]))
	}
	tables, err := parseTables(data[0])
	if err != nil {
		return m, err
	}
	// T02's only permitted additive pin. This remains a spec/hash checker;
	// transcript crypto and release readiness are tested by noisesession.
	const transcript = "protocol/vectors/nk-transcript.json"
	if b, e := os.ReadFile(filepath.Join(root, filepath.FromSlash(transcript))); e == nil {
		if _, e = strictJSON(b); e != nil {
			return m, fmt.Errorf("transcript JSON: %w", e)
		}
		m.Files[transcript] = fmt.Sprintf("%x", sha256.Sum256(b))
	} else if !errors.Is(e, os.ErrNotExist) {
		return m, e
	}
	return m, validateVectors(data[1], tables)
}

func checkManifest(root string, want manifest) error {
	data, err := os.ReadFile(filepath.Join(root, "protocol", "manifest.json"))
	if err != nil {
		return err
	}
	v, err := strictJSON(data)
	if err != nil {
		return err
	}
	fields, ok := v.(map[string]any)
	if !ok || len(fields) != 2 {
		return errors.New("manifest needs exactly protocol_version and files")
	}
	if _, ok := fields["protocol_version"]; !ok {
		return errors.New("manifest missing protocol_version")
	}
	if _, ok := fields["files"]; !ok {
		return errors.New("manifest missing files")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	var got manifest
	if err = d.Decode(&got); err != nil {
		return err
	}
	if !reflect.DeepEqual(got, want) {
		return fmt.Errorf("manifest version/file set/SHA-256 mismatch: expected %+v", want)
	}
	return nil
}

func run(root string, write bool) error {
	m, err := content(root)
	if err != nil {
		return err
	}
	if write {
		if err := writeManifest(root, m); err != nil {
			return err
		}
	}
	return checkManifest(root, m)
}

func writeManifest(root string, validated manifest) error {
	// Re-read and validate the on-disk documents immediately before pinning.
	// Hash exactly these validated bytes, and refuse changes since the first read.
	fresh, err := content(root)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(fresh, validated) {
		return errors.New("content changed before manifest write")
	}
	b, err := json.MarshalIndent(fresh, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "protocol", "manifest.json"), append(b, '\n'), 0644)
}

func main() {
	root := flag.String("root", ".", "repository root")
	write := flag.Bool("write", false, "explicitly regenerate initial manifest after content validation")
	flag.Parse()
	if err := run(*root, *write); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("spec hashes, human/machine tables, vector references, coverage and wallet expectations match")
}
