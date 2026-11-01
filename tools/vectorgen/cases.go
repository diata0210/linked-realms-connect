package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

func walletCheck(e []byte) int {
	if code := verifyEnvelope(e); code != 0 {
		return code
	}
	b := e[140 : len(e)-64]
	// These fixtures deliberately have no source/profile; exercise optional blob.
	if len(b) < 53 || !bytes.Equal(b[48:52], []byte{0, 0, 0, 0}) {
		return 1
	}
	switch b[52] {
	case 0:
		if len(b) != 53 {
			return 1
		}
	case 1:
		if len(b) < 57 {
			return 1
		}
		n := binary.BigEndian.Uint32(b[53:57])
		if n > 64 || uint64(n)+57 != uint64(len(b)) {
			return 1
		}
	default:
		return 1
	}
	return 0
}

func walletVectors() []M {
	var out []M
	for _, tc := range []struct {
		name    string
		value   []byte
		present bool
		code    int
	}{
		{"absent", nil, false, 0}, {"present", []byte("test-reward-address"), true, 0}, {"present_empty", nil, true, 0}, {"exactly_64", bytes.Repeat([]byte{0x80}, 64), true, 0}, {"65_rejected", bytes.Repeat([]byte{0x80}, 65), true, 1},
	} {
		e := envelope(19, greeting(tc.value, tc.present), playerSeed, land, sid, issued+30)
		must(walletCheck(e) == tc.code, tc.name)
		v := M{"name": tc.name, "kind": ref("kinds", 19), "signing_seed_hex": hex(playerSeed), "present": tc.present, "wallet_hex": hex(tc.value), "body_hex": hex(e[140 : len(e)-64]), "envelope_hex": hex(e), "expect": "accept"}
		if tc.code != 0 {
			v["expect"] = "reject"
			v["error"] = ref("errors", tc.code)
		}
		out = append(out, v)
	}
	e := envelope(19, greeting([]byte("address"), true), playerSeed, land, sid, issued+30)
	e[140+57] ^= 1
	must(walletCheck(e) == 3, "altered wallet must break signature")
	out = append(out, M{"name": "altered_address_breaks_signature", "kind": ref("kinds", 19), "envelope_hex": hex(e), "expect": "reject", "error": ref("errors", 3)})
	return out
}

func primitiveCheck(typ string, b []byte, max int) bool {
	if typ == "bool" {
		return len(b) == 1 && b[0] <= 1
	}
	if len(b) < 4 {
		return false
	}
	n := binary.BigEndian.Uint32(b[:4])
	if uint64(n) > uint64(max) || uint64(n)+4 != uint64(len(b)) {
		return false
	}
	return typ != "text" || utf8.Valid(b[4:])
}

func tableCheck(rows [][2]any, start, count int) bool {
	if len(rows) != count {
		return false
	}
	names := map[string]bool{}
	for i, row := range rows {
		n, ok := row[1].(string)
		if row[0] != start+i || !ok || n == "" || names[n] {
			return false
		}
		names[n] = true
	}
	return true
}

func negativeVectors(all [][]byte) []M {
	var out []M
	add := func(name string, e []byte, code int) {
		must(verifyEnvelope(e) == code, name)
		out = append(out, M{"name": name, "scope": "envelope_header_and_signature", "envelope_hex": hex(e), "expect": "reject", "error": ref("errors", code)})
	}
	add("trailing_byte", cat(all[1], []byte{0}), 1)
	add("truncated_signature", all[1][:203], 1)
	unknown := append([]byte{}, all[1]...)
	binary.BigEndian.PutUint16(unknown[6:8], 33)
	add("unknown_kind_33", unknown, 1)
	version := append([]byte{}, all[1]...)
	version[5] = 2
	add("unsupported_version_2", version, 2)
	oversize := append([]byte{}, all[1]...)
	binary.BigEndian.PutUint32(oversize[136:140], 0xffffffff)
	add("declared_body_ffffffff_before_allocation", oversize, 1)
	for _, offset := range []int{8, 40, 72, 88, 120, 128, 140} {
		e := append([]byte{}, all[19]...)
		e[offset] ^= 1
		add(fmt.Sprintf("signed_field_flip_offset_%d", offset), e, 3)
	}
	e := append([]byte{}, all[19]...)
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(playerSeed), cat([]byte("wrong-domain\x00"), e[:len(e)-64]))
	copy(e[len(e)-64:], sig)
	add("wrong_signature_domain", e, 3)
	for _, part := range []string{"R", "S"} {
		bad := append([]byte{}, all[19]...)
		start := len(bad) - 64
		if part == "S" {
			start += 32
		}
		copy(bad[start:start+32], bytes.Repeat([]byte{0xff}, 32))
		add("noncanonical_signature_"+part, bad, 3)
	}
	for _, tc := range []struct {
		name, typ string
		b         []byte
		max       int
		ok        bool
	}{
		{"invalid_utf8", "text", blob([]byte{0xc0, 0x80}), 32, false},
		{"surrogate_utf8", "text", blob([]byte{0xed, 0xa0, 0x80}), 32, false},
		{"invalid_bool_2", "bool", []byte{2}, 1, false},
		{"bool_trailing", "bool", []byte{1, 0}, 1, false},
		{"text_32", "text", txt(strings.Repeat("a", 32)), 32, true},
		{"text_33_oversize", "text", txt(strings.Repeat("a", 33)), 32, false},
		{"blob_declared_ffffffff", "blob", u32(0xffffffff), 64, false},
		{"blob_trailing", "blob", cat(blob(nil), []byte{0}), 64, false},
	} {
		must(primitiveCheck(tc.typ, tc.b, tc.max) == tc.ok, tc.name)
		v := M{"name": tc.name, "scope": "primitive", "input_type": tc.typ, "input_hex": hex(tc.b), "max_bytes": tc.max, "expect": "reject", "error": ref("errors", 1)}
		if tc.ok {
			v["expect"] = "accept"
			delete(v, "error")
		}
		out = append(out, v)
	}
	for _, tc := range []struct {
		name string
		rows [][2]any
	}{
		{"duplicate_table_code", [][2]any{{1, "ONE"}, {1, "TWO"}}},
		{"noncontiguous_table", [][2]any{{1, "ONE"}, {3, "THREE"}}},
		{"duplicate_table_name", [][2]any{{1, "ONE"}, {2, "ONE"}}},
	} {
		must(!tableCheck(tc.rows, 1, 2), tc.name)
		out = append(out, M{"name": tc.name, "scope": "table_validation", "input_rows": tc.rows, "start": 1, "count": 2, "expect": "reject", "error": ref("errors", 1)})
	}
	return out
}

func parseKeyFile(data []byte) int {
	if len(data) > 2048 || !utf8.Valid(data) {
		return 1
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return 1
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		t, err = d.Token()
		if err != nil {
			return 1
		}
		k, ok := t.(string)
		if !ok {
			return 1
		}
		if _, ok = fields[k]; ok {
			return 1
		}
		var v json.RawMessage
		if d.Decode(&v) != nil {
			return 1
		}
		fields[k] = v
	}
	if _, err = d.Token(); err != nil {
		return 1
	}
	if _, err = d.Token(); err != io.EOF {
		return 1
	}
	allowed := []string{"format", "version", "kind", "algorithm", "public_key", "seed", "created_at", "encryption"}
	if len(fields) != len(allowed) {
		return 1
	}
	for _, k := range allowed {
		if fields[k] == nil {
			return 1
		}
	}
	get := func(k string) string {
		var v string
		if json.Unmarshal(fields[k], &v) != nil {
			return ""
		}
		return v
	}
	if string(fields["version"]) != "2" {
		return 2
	}
	if get("format") != "linked-realms-key" || get("algorithm") != "Ed25519" || get("encryption") != "none" {
		return 1
	}
	kind := get("kind")
	if kind != "player" && kind != "land" && kind != "hub" {
		return 1
	}
	time := get("created_at")
	v, err := strconv.ParseUint(time, 10, 64)
	if err != nil || strconv.FormatUint(v, 10) != time {
		return 1
	}
	decode := func(s string) []byte {
		b, err := base64.RawURLEncoding.Strict().DecodeString(s)
		if err != nil || len(b) != 32 || b64(b) != s {
			return nil
		}
		return b
	}
	seed, public := decode(get("seed")), decode(get("public_key"))
	if seed == nil || public == nil {
		return 1
	}
	if kind != "hub" {
		seed, _ = slip(seed, identityPath)
	}
	if !bytes.Equal(public, pub(seed)) {
		return 3
	}
	return 0
}

func keyFileVectors() []M {
	var out []M
	base := M{"format": "linked-realms-key", "version": 2, "kind": "player", "algorithm": "Ed25519", "public_key": b64(player), "seed": b64(playerRoot), "created_at": "1700000000", "encryption": "none"}
	encode := func(m M) []byte { b, e := json.Marshal(m); check(e); return b }
	add := func(name string, b []byte, code int) {
		must(parseKeyFile(b) == code, name)
		v := M{"name": name, "json_utf8": string(b), "bytes_hex": hex(b), "expect": "accept"}
		if code != 0 {
			v["expect"] = "reject"
			v["error"] = ref("errors", code)
		}
		out = append(out, v)
	}
	add("v2_player", encode(base), 0)
	for _, tc := range []struct {
		name, k string
		v       any
		code    int
	}{
		{"version_1_rejected", "version", 1, 2}, {"unknown_version", "version", 3, 2}, {"wrong_public_key", "public_key", b64(hub), 3}, {"unknown_kind", "kind", "wallet", 1}, {"unknown_field", "extra", true, 1}, {"padded_seed", "seed", b64(playerRoot) + "=", 1}, {"created_at_number", "created_at", 1700000000, 1}, {"created_at_overflow", "created_at", "18446744073709551616", 1},
	} {
		m := M{}
		for k, v := range base {
			m[k] = v
		}
		m[tc.k] = tc.v
		add(tc.name, encode(m), tc.code)
	}
	b := encode(base)
	add("exactly_2048_bytes", append(append([]byte{}, b...), bytes.Repeat([]byte{' '}, 2048-len(b))...), 0)
	add("over_2_KiB", append(append([]byte{}, b...), bytes.Repeat([]byte{' '}, 2049-len(b))...), 1)
	add("duplicate_kind", append([]byte(`{"kind":"player",`), b[1:]...), 1)
	add("trailing_JSON", cat(b, []byte("{}")), 1)
	base["kind"] = "land"
	base["seed"] = b64(landRoot)
	base["public_key"] = b64(land)
	add("v2_land", encode(base), 0)
	base["kind"] = "hub"
	base["seed"] = b64(hubSeed)
	base["public_key"] = b64(hub)
	add("v2_hub_plain_seed", encode(base), 0)
	return out
}

func operationVectors(all [][]byte) []M {
	var out []M
	for op := 1; op <= 12; op++ {
		stream := uint32(1)
		var body []byte
		if op <= 4 {
			stream = 0
		}
		switch op {
		case 1:
			body = blob(all[19])
		case 2, 3:
			body = sid
		case 4, 12:
			body = u16(0)
		case 5:
			body = cat(txt("POST"), txt("/matchmake/joinOrCreate/land"), u16(0), u32(2))
		case 6:
			body = cat(u32(0), []byte{1}, txt("{}"))
		case 7:
			body = cat(u16(200), u16(0), u32(0))
		case 8:
			body = cat(u32(0), []byte{1}, blob(nil))
		case 9:
			body = txt("/process/room?sessionId=session")
		case 10:
			body = nil
		case 11:
			body = cat(u32(0), []byte{1}, u32(0), u32(3), []byte{1}, blob([]byte{1, 2, 3}))
		}
		out = append(out, M{"name": fmt.Sprintf("operation_%02d", op), "op": ref("ops", op), "stream": stream, "body_hex": hex(body), "plaintext_hex": hex(cat(u16(uint16(op)), u32(stream), body)), "scope": "encoding only; HTTP and WS fixtures are independent streams", "expect": "accept"})
	}
	return out
}

func objectVectors() []M {
	p := profile()
	unsigned := p[:len(p)-64]
	msg := cat([]byte("linked-realms/connect/profile/v1\x00"), unsigned)
	must(ed25519.Verify(player, msg, p[len(p)-64:]), "profile verification")
	i := cat([]byte{1}, land, u16(1), endpoint(), challenge, u64(issued+604800))
	imsg := cat([]byte("linked-realms/connect/invite/v1\x00"), i)
	i = cat(i, ed25519.Sign(ed25519.NewKeyFromSeed(landSeed), imsg))
	must(ed25519.Verify(land, imsg, i[len(i)-64:]), "invite verification")
	g := envelope(19, cat(land, sid, []byte{0, 0, 0, 1}, p, []byte{1}, txt("test-reward-address")), playerSeed, land, sid, issued+30)
	must(verifyEnvelope(g) == 0, "profile-wallet greeting signature")
	return []M{
		{"name": "signed_profile_preset", "signing_seed_hex": hex(playerSeed), "signed_bytes_hex": hex(msg), "bytes_hex": hex(p), "expect": "accept"},
		{"name": "invite_link", "signing_seed_hex": hex(landSeed), "signed_bytes_hex": hex(imsg), "bytes_hex": hex(i), "url": "linkedrealms://invite/" + b64(i), "expect": "accept"},
		{"name": "greeting_inline_profile_and_wallet", "kind": ref("kinds", 19), "signing_seed_hex": hex(playerSeed), "body_hex": hex(g[140 : len(g)-64]), "envelope_hex": hex(g), "expect": "accept"},
	}
}

func frameCheck(frame []byte, next uint64) int {
	if len(frame) == 0 || len(frame) > 32768 {
		return 1
	}
	if frame[0] == 0 {
		return verifyEnvelope(frame[1:])
	}
	if len(frame) < 31 || frame[0] > 2 {
		return 1
	}
	if binary.BigEndian.Uint16(frame[1:3]) != 1 {
		return 2
	}
	if !bytes.Equal(frame[3:19], route) {
		return 1
	}
	n := binary.BigEndian.Uint32(frame[27:31])
	if uint64(n)+31 != uint64(len(frame)) {
		return 1
	}
	seq := binary.BigEndian.Uint64(frame[19:27])
	if frame[0] == 1 {
		if seq != 0 || n > 4096 || n < 36 {
			return 1
		}
		if uint64(binary.BigEndian.Uint32(frame[63:67]))+36 != uint64(n) {
			return 1
		}
	} else {
		if n < 16 || n > 32737 {
			return 1
		}
		if seq != next {
			return 5
		}
	}
	return 0
}

func frameVectors(all [][]byte) []M {
	makeFrame := func(typ byte, seq uint64, payload []byte) []byte {
		return cat([]byte{typ}, u16(1), route, u64(seq), u32(uint32(len(payload))), payload)
	}
	// Deliberately placeholder crypto bytes: these cases test framing/AD, NOT Noise.
	handshake := makeFrame(1, 0, cat(hash(all[7]), blob(bytes.Repeat([]byte{0x77}, 48))))
	transport := makeFrame(2, 0, bytes.Repeat([]byte{0x88}, 16))
	var out []M
	add := func(name string, frame []byte, next uint64, code int) {
		must(frameCheck(frame, next) == code, name)
		v := M{"name": name, "scope": "framing only; placeholder ciphertext/handshake NOT cryptographically valid", "frame_hex": hex(frame), "next_sequence": strconv.FormatUint(next, 10), "expect": "accept"}
		if len(frame) >= 31 && frame[0] == 2 {
			v["associated_data_hex"] = hex(frame[:31])
		}
		if code != 0 {
			v["expect"] = "reject"
			v["error"] = ref("errors", code)
		}
		out = append(out, v)
	}
	add("control_record", cat([]byte{0}, all[1]), 0, 0)
	add("handshake_record", handshake, 0, 0)
	add("transport_empty_plaintext_header", transport, 0, 0)
	add("transport_max_record", makeFrame(2, 0, bytes.Repeat([]byte{0x88}, 32737)), 0, 0)
	add("transport_repeated_sequence", transport, 1, 5)
	add("transport_skipped_sequence", makeFrame(2, 1, bytes.Repeat([]byte{0x88}, 16)), 0, 5)
	bad := append([]byte{}, transport...)
	bad[3] ^= 1
	add("wrong_route", bad, 0, 1)
	bad = append([]byte{}, transport...)
	bad[2] = 2
	add("wrong_frame_version", bad, 0, 2)
	bad = append([]byte{}, transport...)
	binary.BigEndian.PutUint32(bad[27:31], 32738)
	add("over_max_declared_ciphertext", bad, 0, 1)
	add("handshake_payload_4097", makeFrame(1, 0, cat(hash(all[7]), blob(bytes.Repeat([]byte{0x77}, 4061)))), 0, 1)
	return out
}

func timeVectors() []M {
	var out []M
	for _, tc := range []struct {
		name                 string
		issued, expires, now uint64
		ok                   bool
	}{
		{"future_at_120", 1120, 1180, 1000, true}, {"future_121", 1121, 1181, 1000, false}, {"expiry_at_minus_120", 820, 880, 1000, true}, {"expiry_minus_121", 819, 879, 1000, false}, {"lifetime_61", 1000, 1061, 1000, false}, {"issue_after_expiry", 1001, 1000, 1000, false},
	} {
		ok := tc.issued <= tc.expires && tc.expires-tc.issued <= 60 && tc.issued <= tc.now+120 && tc.expires+120 >= tc.now
		must(ok == tc.ok, tc.name)
		v := M{"name": tc.name, "issued_at": strconv.FormatUint(tc.issued, 10), "expires_at": strconv.FormatUint(tc.expires, 10), "now": strconv.FormatUint(tc.now, 10), "scope": "generic 60-second envelope, excludes monotonic deadline checks", "expect": "accept"}
		if !ok {
			v["expect"] = "reject"
			v["error"] = ref("errors", 4)
		} else {
			retain := tc.expires + 120 - tc.now
			if retain < 180 {
				retain = 180
			}
			v["minimum_retention_seconds"] = retain
		}
		out = append(out, v)
	}
	return out
}
