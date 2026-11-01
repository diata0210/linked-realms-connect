package protocol

import (
	"bytes"
	"testing"
)

// This test can also run using only codec.go/codes.go while external crypto
// downloads are blocked. It makes no signature or cryptographic test claim.
func TestCanonicalPrimitives(t *testing.T) {
	for _, tc := range []struct {
		name, typ string
		max       int
		raw       []byte
		valid     bool
	}{
		{"strict_utf8", "text", 32, []byte{0, 0, 0, 2, 0xc0, 0x80}, false},
		{"surrogate", "text", 32, []byte{0, 0, 0, 3, 0xed, 0xa0, 0x80}, false},
		{"huge_length", "blob", 64, []byte{255, 255, 255, 255}, false},
		{"bad_bool", "bool", 0, []byte{2}, false},
		{"bool_trailing", "bool", 0, []byte{1, 0}, false},
		{"absent", "?blob", 64, []byte{0}, true},
		{"present_empty", "?blob", 64, []byte{1, 0, 0, 0, 0}, true},
		{"optional_bad_tag", "?blob", 64, []byte{2}, false},
		{"empty_text", "text", 32, []byte{0, 0, 0, 0}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := DecodePrimitive(tc.raw, tc.typ, tc.max)
			if (err == nil) != tc.valid {
				t.Fatalf("%v", err)
			}
			if err == nil {
				b, err := putValue(nil, tc.typ, tc.max, v)
				if err != nil || !bytes.Equal(b, tc.raw) {
					t.Fatal("round trip", err)
				}
			}
		})
	}
	for _, v := range []any{uint64(256), int(1), "1"} {
		if _, err := putValue(nil, "u8", 0, v); err != Malformed {
			t.Fatal("invalid numeric input")
		}
	}
	if _, err := putValue(nil, "key", 0, make([]byte, 31)); err != Malformed {
		t.Fatal("short key")
	}
	if _, err := putObject(nil, fields("value:u8"), Values{"value": uint64(1), "extra": uint64(0)}); err != Malformed {
		t.Fatal("unknown field")
	}
}
