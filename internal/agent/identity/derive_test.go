package identity

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	p "github.com/diata0210/linked-realms-connect/protocol-go"
	"os"
	"strconv"
	"strings"
	"testing"
)

func unhex(s string) []byte {
	b, e := hex.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return b
}
func TestFrozenDerivationsAndKeyFiles(t *testing.T) {
	b, e := os.ReadFile("../../../protocol/vectors/v1.json")
	if e != nil {
		t.Fatal(e)
	}
	var v map[string][]map[string]json.RawMessage
	var top map[string]json.RawMessage
	json.Unmarshal(b, &top)
	v = map[string][]map[string]json.RawMessage{}
	for _, g := range []string{"derivations", "known_answer", "key_files"} {
		var rows []map[string]json.RawMessage
		if e = json.Unmarshal(top[g], &rows); e != nil {
			t.Fatal(e)
		}
		v[g] = rows
	}
	for group, rows := range v {
		for _, row := range rows {
			s := func(k string) string { var x string; json.Unmarshal(row[k], &x); return x }
			t.Run(group+"/"+s("name"), func(t *testing.T) {
				if group == "key_files" {
					_, err := DecodeKeyFile(unhex(s("bytes_hex")))
					if s("expect") == "reject" {
						var expected struct{ Code int }
						json.Unmarshal(row["error"], &expected)
						if err != p.Code(expected.Code) {
							t.Fatalf("%v != %d", err, expected.Code)
						}
					} else if err != nil {
						t.Fatal(err)
					}
					return
				}
				var d Derived
				var err error
				if group == "derivations" {
					d, err = Derive(unhex(s("root_seed_hex")), s("profile"))
				} else {
					var path []uint32
					for _, part := range strings.Split(s("path"), "/")[1:] {
						n, e := strconv.ParseUint(strings.TrimSuffix(part, "'"), 10, 31)
						if e != nil {
							t.Fatal(e)
						}
						path = append(path, uint32(n)|1<<31)
					}
					d, err = derive(unhex(s("seed_hex")), strings.Contains(s("name"), "BIP32"), path)
				}
				if err != nil {
					t.Fatal(err)
				}
				for name, got := range map[string][]byte{"private_hex": d.Private, "chain_code_hex": d.Chain, "public_hex": d.Public} {
					if name == "public_hex" && s(name) == "" && group == "known_answer" {
						continue
					}
					if !bytes.Equal(got, unhex(s(name))) {
						t.Fatal(name)
					}
				}
			})
		}
	}
}
func FuzzKeyFile(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = DecodeKeyFile(b) })
}
