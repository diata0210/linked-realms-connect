package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// These are T01 coverage requirements, checked before reading or writing the
// manifest. A new hash cannot bless a missing category or wallet expectation.
func validateCoverage(top map[string]any) error {
	categories := map[string]map[string]map[string]any{}
	names := map[string]bool{}
	for _, category := range []string{"envelopes", "operations", "derivations", "known_answer", "key_files", "wallet", "negative", "time", "objects", "frames", "quest_pagination"} {
		rows, ok := top[category].([]any)
		if !ok || len(rows) == 0 {
			return fmt.Errorf("missing/empty vector category %s", category)
		}
		cases := map[string]map[string]any{}
		for _, value := range rows {
			row, ok := value.(map[string]any)
			if !ok {
				return fmt.Errorf("%s: case must be object", category)
			}
			name, ok := row["name"].(string)
			if !ok || strings.TrimSpace(name) == "" || names[name] {
				return fmt.Errorf("%s: empty/duplicate case name %q", category, name)
			}
			names[name] = true
			cases[name] = row
			if category != "derivations" && category != "known_answer" {
				expect, hasError := row["expect"], row["error"] != nil
				if expect != "accept" && expect != "reject" || (expect == "reject") != hasError {
					return fmt.Errorf("%s/%s: invalid expect/error pair", category, name)
				}
			}
		}
		categories[category] = cases
	}
	if prologue, ok := top["prologue"].(map[string]any); !ok || prologue["bytes_hex"] == nil {
		return fmt.Errorf("missing prologue bytes")
	}

	for _, set := range []struct {
		category, prefix, reference, bytesField string
		count                                   int
	}{
		{"envelopes", "signed_kind", "kind", "envelope_hex", 32},
		{"operations", "operation", "op", "plaintext_hex", 12},
	} {
		for code := 1; code <= set.count; code++ {
			name := fmt.Sprintf("%s_%02d", set.prefix, code)
			row := categories[set.category][name]
			ref, _ := row[set.reference].(map[string]any)
			got, err := number(ref["code"])
			encoded, _ := row[set.bytesField].(string)
			data, hexErr := hex.DecodeString(encoded)
			if err != nil || got != code || row["expect"] != "accept" || hexErr != nil || len(data) == 0 {
				return fmt.Errorf("missing/invalid %s case %s", set.category, name)
			}
		}
	}

	seeds := map[string]map[string]bool{}
	for name, row := range categories["derivations"] {
		seed, _ := row["root_seed_hex"].(string)
		decoded, err := hex.DecodeString(seed)
		profile, _ := row["profile"].(string)
		if err != nil || len(decoded) != 32 || seed != strings.ToLower(seed) || (profile != "identity" && profile != "wallet_A" && profile != "wallet_B") {
			return fmt.Errorf("invalid derivation seed/profile in %s", name)
		}
		if seeds[seed] == nil {
			seeds[seed] = map[string]bool{}
		}
		if seeds[seed][profile] {
			return fmt.Errorf("duplicate derivation seed/profile in %s", name)
		}
		seeds[seed][profile] = true
		path, publicSize := "m/1'/0'", 32
		if profile == "identity" {
			path = "m/0'/0'"
		} else if profile == "wallet_A" {
			publicSize = 33
		}
		if row["path"] != path {
			return fmt.Errorf("derivations/%s: invalid path", name)
		}
		if err := validateKeyOutputs(row, publicSize); err != nil {
			return fmt.Errorf("derivations/%s: %w", name, err)
		}
	}
	if len(seeds) < 3 {
		return fmt.Errorf("derivations require at least three distinct seeds")
	}
	for seed, profiles := range seeds {
		if len(profiles) != 3 {
			return fmt.Errorf("seed %s needs identity, wallet_A and wallet_B", seed)
		}
	}

	// Pin mandatory case presence independently of generated content hashes.
	for name, code := range map[string]int{
		"quest_query_cursor_absent": 29, "quest_query_cursor_present": 29,
		"quest_page_shared_id_order": 30, "quest_page_after_cursor": 30,
	} {
		row := categories["quest_pagination"][name]
		kind, _ := row["kind"].(map[string]any)
		got, err := number(kind["code"])
		if err != nil || got != code || row["expect"] != "accept" {
			return fmt.Errorf("missing/invalid quest pagination case %s", name)
		}
		if err := validateQuest(row, name, code); err != nil {
			return fmt.Errorf("quest_pagination/%s: %w", name, err)
		}
	}
	required := map[string][]string{
		"known_answer": {
			"SLIP-0010 test vector 1 for ed25519 / m", "SLIP-0010 test vector 1 for ed25519 / m/0'",
			"BIP32 test vector 1 / m", "BIP32 test vector 1 / m/0'", "BIP32 test vector 4 / m/0'/1' (leading zeros)",
		},
		"key_files": {
			"v2_player", "v2_land", "v2_hub_plain_seed", "version_1_rejected", "unknown_version", "wrong_public_key",
			"unknown_kind", "unknown_field", "padded_seed", "created_at_number", "created_at_overflow",
			"exactly_2048_bytes", "over_2_KiB", "duplicate_kind", "trailing_JSON",
		},
		"negative": {
			"trailing_byte", "truncated_signature", "unknown_kind_33", "unsupported_version_2", "declared_body_ffffffff_before_allocation",
			"signed_field_flip_offset_8", "signed_field_flip_offset_40", "signed_field_flip_offset_72", "signed_field_flip_offset_88",
			"signed_field_flip_offset_120", "signed_field_flip_offset_128", "signed_field_flip_offset_140", "wrong_signature_domain",
			"noncanonical_signature_R", "noncanonical_signature_S", "invalid_utf8", "surrogate_utf8", "invalid_bool_2", "bool_trailing",
			"text_32", "text_33_oversize", "blob_declared_ffffffff", "blob_trailing", "duplicate_table_code", "noncontiguous_table", "duplicate_table_name",
		},
		"time": {"future_at_120", "future_121", "expiry_at_minus_120", "expiry_minus_121", "lifetime_61", "issue_after_expiry"},
	}
	for category, requiredNames := range required {
		for _, name := range requiredNames {
			if categories[category][name] == nil {
				return fmt.Errorf("missing %s case %s", category, name)
			}
			if category == "negative" {
				want := "reject"
				if name == "text_32" {
					want = "accept"
				}
				if categories[category][name]["expect"] != want {
					return fmt.Errorf("negative/%s: expected %s", name, want)
				}
			}
		}
	}
	for name, row := range categories["known_answer"] {
		seedSize, publicSize, path := 16, 32, "m"
		if strings.Contains(name, "BIP32") {
			publicSize = 33
			xprv, ok := row["xprv"].(string)
			if !ok || len(xprv) != 111 || !strings.HasPrefix(xprv, "xprv") || strings.Trim(xprv, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz") != "" {
				return fmt.Errorf("known_answer/%s: invalid xprv", name)
			}
		}
		if strings.Contains(name, "/ m/0'") {
			path = "m/0'"
		}
		if name == "BIP32 test vector 4 / m/0'/1' (leading zeros)" {
			seedSize, publicSize, path = 32, 0, "m/0'/1'"
		}
		if _, err := hexField(row, "seed_hex", seedSize, seedSize); err != nil {
			return fmt.Errorf("known_answer/%s: %w", name, err)
		}
		if row["path"] != path {
			return fmt.Errorf("known_answer/%s: invalid path", name)
		}
		if err := validateKeyOutputs(row, publicSize); err != nil {
			return fmt.Errorf("known_answer/%s: %w", name, err)
		}
	}
	// Both acceptance and rejection must remain represented in the key-file set.
	for name, row := range categories["key_files"] {
		want := "reject"
		switch name {
		case "v2_player", "v2_land", "v2_hub_plain_seed", "exactly_2048_bytes":
			want = "accept"
		}
		if row["expect"] != want {
			return fmt.Errorf("key_files/%s: expected %s", name, want)
		}
	}
	for name, code := range map[string]int{"absent": 0, "present": 0, "present_empty": 0, "exactly_64": 0, "65_rejected": 1, "altered_address_breaks_signature": 3} {
		row := categories["wallet"][name]
		kind, _ := row["kind"].(map[string]any)
		kindCode, err := number(kind["code"])
		if err != nil || kindCode != 19 {
			return fmt.Errorf("missing/invalid GREETING wallet case %s", name)
		}
		if _, err := hexField(row, "envelope_hex", 204, -1); err != nil {
			return fmt.Errorf("wallet/%s: %w", name, err)
		}
		if code == 0 {
			if row["expect"] != "accept" || row["error"] != nil {
				return fmt.Errorf("wallet/%s: expected accept", name)
			}
		} else {
			ref, _ := row["error"].(map[string]any)
			got, err := number(ref["code"])
			if row["expect"] != "reject" || err != nil || got != code {
				return fmt.Errorf("wallet/%s: expected rejection code %d", name, code)
			}
		}
	}
	ack, err := envelopeBody(categories["envelopes"]["signed_kind_08"], 8, 66)
	if err != nil {
		return fmt.Errorf("ACK: %w", err)
	}
	heartbeat := categories["envelopes"]["signed_kind_12"]
	if _, err := envelopeBody(heartbeat, 12, 24); err != nil {
		return fmt.Errorf("HEARTBEAT: %w", err)
	}
	request, _ := hexField(heartbeat, "envelope_hex", 204, -1)
	wantHash := sha256.Sum256(request)
	if !bytes.Equal(ack[:32], wantHash[:]) {
		return fmt.Errorf("ACK request_hash must equal SHA-256 of HEARTBEAT envelope")
	}
	return validateFrames(categories)
}

// These fixtures intentionally contain opaque placeholder crypto payloads.
// Check their framing inputs and named boundary conditions, not Noise validity.
func validateFrames(categories map[string]map[string]map[string]any) error {
	offer, err := envelopeBody(categories["envelopes"]["signed_kind_14"], 14, 72)
	if err != nil {
		return fmt.Errorf("frame route reference: %w", err)
	}
	for _, tc := range []struct {
		name                         string
		typ, size, version, declared int
		sequence, next               uint64
		code                         int
	}{
		{"control_record", 0, 205, 0, 0, 0, 0, 0},
		{"handshake_record", 1, 115, 1, 84, 0, 0, 0},
		{"transport_empty_plaintext_header", 2, 47, 1, 16, 0, 0, 0},
		{"transport_max_record", 2, 32768, 1, 32737, 0, 0, 0},
		{"transport_repeated_sequence", 2, 47, 1, 16, 0, 1, 5},
		{"transport_skipped_sequence", 2, 47, 1, 16, 1, 0, 5},
		{"wrong_route", 2, 47, 1, 16, 0, 0, 1},
		{"wrong_frame_version", 2, 47, 2, 16, 0, 0, 2},
		{"over_max_declared_ciphertext", 2, 47, 1, 32738, 0, 0, 1},
		{"handshake_payload_4097", 1, 4128, 1, 4097, 0, 0, 1},
	} {
		row := categories["frames"][tc.name]
		frame, err := hexField(row, "frame_hex", tc.size, tc.size)
		if err != nil {
			return fmt.Errorf("frames/%s: %w", tc.name, err)
		}
		want := "accept"
		if tc.code != 0 {
			want = "reject"
			ref, _ := row["error"].(map[string]any)
			code, err := number(ref["code"])
			if err != nil || code != tc.code {
				return fmt.Errorf("frames/%s: expected error %d", tc.name, tc.code)
			}
		}
		if row["expect"] != want || row["next_sequence"] != fmt.Sprint(tc.next) || int(frame[0]) != tc.typ {
			return fmt.Errorf("frames/%s: invalid expectation/next sequence/type", tc.name)
		}
		if tc.typ == 0 {
			control, err := hexField(categories["envelopes"]["signed_kind_01"], "envelope_hex", 204, 204)
			if err != nil || !bytes.Equal(frame[1:], control) {
				return fmt.Errorf("frames/%s: control envelope mismatch", tc.name)
			}
			continue
		}
		route := append([]byte(nil), offer[56:72]...)
		if tc.name == "wrong_route" {
			route[0] ^= 1
		}
		if int(binary.BigEndian.Uint16(frame[1:3])) != tc.version || !bytes.Equal(frame[3:19], route) || binary.BigEndian.Uint64(frame[19:27]) != tc.sequence || int(binary.BigEndian.Uint32(frame[27:31])) != tc.declared {
			return fmt.Errorf("frames/%s: header/boundary mismatch", tc.name)
		}
		if tc.typ == 2 {
			ad, err := hexField(row, "associated_data_hex", 31, 31)
			if err != nil || !bytes.Equal(ad, frame[:31]) {
				return fmt.Errorf("frames/%s: associated data must equal header", tc.name)
			}
		} else {
			card, err := hexField(categories["envelopes"]["signed_kind_07"], "envelope_hex", 204, -1)
			hash := sha256.Sum256(card)
			if err != nil || !bytes.Equal(frame[31:63], hash[:]) || uint64(binary.BigEndian.Uint32(frame[63:67])) != uint64(len(frame)-67) {
				return fmt.Errorf("frames/%s: handshake card/payload length mismatch", tc.name)
			}
		}
	}
	return nil
}

// A negative maximum means no upper bound; exact fields use min == max.
func hexField(row map[string]any, field string, min, max int) ([]byte, error) {
	s, ok := row[field].(string)
	b, err := hex.DecodeString(s)
	if !ok || err != nil || len(b) < min || (max >= 0 && len(b) > max) {
		return nil, fmt.Errorf("missing/invalid %s (hex bytes %d..%d)", field, min, max)
	}
	return b, nil
}

func validateKeyOutputs(row map[string]any, publicSize int) error {
	fields := map[string]int{"private_hex": 32, "chain_code_hex": 32}
	// The published BIP32 leading-zero case supplies xprv, private and chain only.
	if publicSize != 0 {
		fields["public_hex"] = publicSize
	}
	for field, size := range fields {
		b, err := hexField(row, field, size, size)
		if err != nil {
			return err
		}
		if bytes.Equal(b, make([]byte, size)) {
			return fmt.Errorf("%s must not be zero", field)
		}
		if field == "public_hex" && size == 33 && b[0] != 2 && b[0] != 3 {
			return fmt.Errorf("public_hex must be compressed secp256k1")
		}
	}
	return nil
}

func envelopeBody(row map[string]any, kind, minimum int) ([]byte, error) {
	body, err := hexField(row, "body_hex", minimum, -1)
	if err != nil {
		return nil, err
	}
	envelope, err := hexField(row, "envelope_hex", 204+minimum, -1)
	if err != nil {
		return nil, err
	}
	if string(envelope[:4]) != "LRC1" || binary.BigEndian.Uint16(envelope[4:6]) != 1 || int(binary.BigEndian.Uint16(envelope[6:8])) != kind || uint64(binary.BigEndian.Uint32(envelope[136:140])) != uint64(len(body)) || len(envelope) != 204+len(body) || !bytes.Equal(envelope[140:len(envelope)-64], body) {
		return nil, fmt.Errorf("envelope header/length/body mismatch")
	}
	return body, nil
}

func questTuple(row map[string]any, field string) ([]byte, error) {
	tuple, ok := row[field].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("missing %s tuple", field)
	}
	id, err := hexField(tuple, "quest_id_hex", 16, 16)
	if err != nil {
		return nil, err
	}
	poster, err := hexField(tuple, "poster_key_hex", 32, 32)
	if err != nil {
		return nil, err
	}
	return append(id, poster...), nil
}

func validateQuest(row map[string]any, name string, kind int) error {
	minimum := 3
	if kind == 30 {
		minimum = 59 // Hub prefix56 + optional cursor flag + count16.
	}
	body, err := envelopeBody(row, kind, minimum)
	if err != nil {
		return err
	}
	offset, field := 0, "cursor"
	if kind == 30 {
		offset, field = 56, "next"
	}
	hasCursor := name == "quest_query_cursor_present" || name == "quest_page_shared_id_order"
	flag := byte(0)
	if hasCursor {
		flag = 1
	}
	if body[offset] != flag {
		return fmt.Errorf("invalid %s flag", field)
	}
	offset++
	var cursor []byte
	if hasCursor {
		cursor, err = questTuple(row, field)
		if err != nil {
			return err
		}
		if len(body) < offset+48+2 || !bytes.Equal(body[offset:offset+48], cursor) {
			return fmt.Errorf("%s must encode quest_id16 + poster_key32", field)
		}
		offset += 48
	} else if row[field] != nil {
		return fmt.Errorf("unexpected %s metadata", field)
	}
	count := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if kind == 29 {
		if count < 1 || count > 64 || len(body) != offset {
			return fmt.Errorf("invalid quest query limit/body length")
		}
		return nil
	}
	tuples, ok := row["ordered_tuples_hex"].([]any)
	if !ok || count != len(tuples) || count != 2 {
		return fmt.Errorf("quest page requires two ordered tuples")
	}
	var previous []byte
	for _, value := range tuples {
		tuple, err := hexField(map[string]any{"tuple": value}, "tuple", 48, 48)
		if err != nil {
			return err
		}
		if previous != nil && bytes.Compare(previous, tuple) >= 0 {
			return fmt.Errorf("quest tuples out of order")
		}
		if len(body)-offset < 4 {
			return fmt.Errorf("missing quest card length")
		}
		size := uint64(binary.BigEndian.Uint32(body[offset : offset+4]))
		offset += 4
		if size < 204+48 || size > uint64(len(body)-offset) {
			return fmt.Errorf("invalid quest card size")
		}
		card := body[offset : offset+int(size)]
		if !bytes.Equal(card[140:188], tuple) || !bytes.Equal(card[8:40], tuple[16:]) {
			return fmt.Errorf("quest card/tuple/poster mismatch")
		}
		offset += int(size)
		previous = tuple
	}
	if offset != len(body) || (hasCursor && !bytes.Equal(cursor, previous)) {
		return fmt.Errorf("quest page trailing bytes or next tuple mismatch")
	}
	return nil
}
