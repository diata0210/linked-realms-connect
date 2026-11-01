// vectorgen is an offline fixture builder, not a production protocol implementation.
// All seeds/nonces/times here are public fixed test inputs. Never use them as keys.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	hexencoding "encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type M = map[string]any

var tables map[string][][2]json.RawMessage

const domain = "linked-realms/connect/control/v1\x00"

// Fixed roots cover zero entropy, ascending bytes and a high-bit-set root.
var playerRoot = unhex("0000000000000000000000000000000000000000000000000000000000000000")
var landRoot = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
var hubSeed = unhex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0")
var playerSeed, _ = slip(playerRoot, identityPath)
var landSeed, _ = slip(landRoot, identityPath)
var player, land, hub = pub(playerSeed), pub(landSeed), pub(hubSeed)
var sid = bytes.Repeat([]byte{0x11}, 16)
var boot = bytes.Repeat([]byte{0x22}, 16)
var connection = bytes.Repeat([]byte{0x33}, 16)
var route = bytes.Repeat([]byte{0x44}, 16)
var challenge = bytes.Repeat([]byte{0x55}, 32)

const issued uint64 = 1700000000

func hex(b []byte) string        { return fmt.Sprintf("%x", b) }
func unhex(s string) []byte      { b, e := hexencoding.DecodeString(s); check(e); return b }
func u16(n uint16) []byte        { return binary.BigEndian.AppendUint16(nil, n) }
func u32(n uint32) []byte        { return binary.BigEndian.AppendUint32(nil, n) }
func u64(n uint64) []byte        { return binary.BigEndian.AppendUint64(nil, n) }
func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
func blob(b []byte) []byte       { return cat(u32(uint32(len(b))), b) }
func txt(s string) []byte        { return blob([]byte(s)) }
func z(n int) []byte             { return make([]byte, n) }
func hash(b []byte) []byte       { h := sha256.Sum256(b); return h[:] }
func b64(b []byte) string        { return base64.RawURLEncoding.EncodeToString(b) }
func ref(table string, code int) M {
	for _, r := range tables[table] {
		var c int
		var n string
		check(json.Unmarshal(r[0], &c))
		check(json.Unmarshal(r[1], &n))
		if c == code {
			return M{"code": c, "name": n}
		}
	}
	panic("missing reference")
}
func endpoint() []byte { return cat(txt("https://hub.example"), hub) }

func envelope(kind uint16, body, seed, recipient, context []byte, expiry uint64) []byte {
	nonce := hash(cat([]byte("public-test-nonce"), u16(kind), body, context))
	header := cat([]byte("LRC1"), u16(1), u16(kind), pub(seed), recipient, context, nonce, u64(issued), u64(expiry), u32(uint32(len(body))))
	must(len(header) == 140, "header length")
	message := cat([]byte(domain), header, body)
	return cat(header, body, ed25519.Sign(ed25519.NewKeyFromSeed(seed), message))
}

// Header/length/signature only. Runtime role/state and full bodies are T02.
func verifyEnvelope(e []byte) int {
	if len(e) < 204 || string(e[:4]) != "LRC1" {
		return 1
	}
	if binary.BigEndian.Uint16(e[4:6]) != 1 {
		return 2
	}
	k := binary.BigEndian.Uint16(e[6:8])
	if k < 1 || k > 32 {
		return 1
	}
	if uint64(binary.BigEndian.Uint32(e[136:140]))+204 != uint64(len(e)) {
		return 1
	}
	if !ed25519.Verify(e[8:40], cat([]byte(domain), e[:len(e)-64]), e[len(e)-64:]) {
		return 3
	}
	return 0
}

func greeting(wallet []byte, present bool) []byte {
	body := cat(land, sid, []byte{0, 0, 0, 0}) // class, absent source, arrival, absent profile
	if !present {
		return append(body, 0)
	}
	return cat(body, []byte{1}, blob(wallet))
}

func profile() []byte {
	b := cat(player, u64(1), txt("Player"), []byte{0}, txt("default"))
	return cat(b, ed25519.Sign(ed25519.NewKeyFromSeed(playerSeed), cat([]byte("linked-realms/connect/profile/v1\x00"), b)))
}

func fixtureEnvelopes() ([]M, [][]byte) {
	cardBody := cat(land, txt("Test Land"), txt("Public fixture"), bytes.Repeat([]byte{0x66}, 32), []byte{0}, u16(1), endpoint(), u16(1), u16(64), u16(1), u64(1), u64(1), []byte{0})
	card := envelope(7, cardBody, landSeed, z(32), z(16), issued+600)
	questBody := cat(route, player, land, txt("Test quest"), txt("fixture"), u16(1), txt("stone"), u64(1), u64(0), u64(issued+600), u64(1))
	quest := envelope(26, questBody, playerSeed, z(32), z(16), issued+600)
	all := make([][]byte, 33)
	// ACK precedes HEARTBEAT in numeric order; build its exact request first.
	all[12] = envelope(12, cat(connection, u64(0)), playerSeed, hub, connection, issued+60)
	var out []M
	for kind := 1; kind <= 32; kind++ {
		seed, recipient, context := playerSeed, hub, connection
		expiry := issued + 60
		var body []byte
		hubReply := false
		switch kind {
		case 1:
			context = z(16)
		case 2:
			hubReply = true
			context = boot
			body = cat(txt("https://hub.example"), u16(1), u16(1), u32(32768), u32(4096), u32(80), u32(8))
		case 3:
			context = boot
			body = cat([]byte{1}, land, []byte{0}, u16(64))
		case 4:
			hubReply = true
			context = boot
			body = cat([]byte{0}, u16(1), blob(card), []byte{1}, u64(issued))
		case 5:
			seed = landSeed
			body = blob(card)
		case 6:
			hubReply = true
			recipient = land
			body = cat(hash(card), u64(1))
		case 7:
			seed = landSeed
			recipient = z(32)
			context = z(16)
			body = cardBody
			expiry = issued + 600
		case 8:
			hubReply = true
			body = cat(u16(12), u64(0))
		case 9:
			hubReply = true
			recipient = z(32)
			context = z(16)
			body = cat(connection, challenge, []byte{0})
		case 10:
			body = cat(hash(all[9]), boot, []byte{0, 0})
		case 11:
			hubReply = true
			body = connection
		case 12:
			body = cat(connection, u64(0))
		case 13:
			body = cat(land, sid, hash(card))
		case 14:
			hubReply = true
			recipient = land
			body = cat(route, player, sid, hash(card), txt("203.0.113.1"))
		case 15:
			hubReply = true
			body = cat(route, sid)
		case 16:
			body = cat(route, u16(0))
		case 17:
			hubReply = true
			body = cat(u16(10), u32(1))
		case 18:
			hubReply = true
			body = u64(issued + 30)
		case 19:
			recipient = land
			context = sid
			body = greeting(nil, false)
		case 20:
			seed = landSeed
			recipient = player
			context = sid
			body = cat(hash(all[19]), challenge, boot, u64(1), u64(issued+30))
		case 21:
			recipient = land
			context = sid
			body = cat(hash(all[20]), challenge, hash([]byte("placeholder-completed-handshake-for-signature-fixture")), boot, sid, []byte{0})
		case 22:
			seed = landSeed
			recipient = player
			context = sid
			body = cat(hash(all[21]), route, player, land, sid, u64(1), u64(1), u64(issued+30))
		case 23:
			seed = landSeed
			recipient = player
			context = sid
			body = cat(hash(all[21]), u16(7))
		case 24:
			seed = landSeed
			recipient = player
			context = sid
			body = cat(u64(2), []byte{1}, u16(6))
		case 25:
			seed = landSeed
			recipient = land
			context = boot
			body = cat(u64(2), []byte{1}, u16(6))
		case 26:
			recipient = z(32)
			context = z(16)
			body = questBody
			expiry = issued + 600
		case 27:
			context = boot
			body = blob(quest)
		case 28:
			context = boot
			body = cat(route, u64(2))
		case 29:
			context = boot
			body = cat([]byte{0}, u16(64))
		case 30:
			hubReply = true
			context = boot
			body = cat([]byte{0}, u16(1), blob(quest))
		case 31:
			recipient = land
			context = sid
			body = cat(hash(quest), route, player, u64(1))
		case 32:
			seed = landSeed
			recipient = player
			context = sid
			body = cat(hash(all[31]), route, []byte{1}, route)
		}
		if kind >= 9 && kind <= 11 || kind >= 19 && kind <= 23 {
			expiry = issued + 30
		}
		if hubReply {
			seed = hubSeed
			if bytes.Equal(recipient, hub) {
				recipient = player
			}
			requestHash := z(32)
			request := map[int]int{2: 1, 4: 3, 6: 5, 8: 12, 11: 10, 15: 13, 30: 29}[kind]
			if request != 0 {
				requestHash = hash(all[request])
			}
			body = cat(requestHash, u64(issued), boot, body)
		}
		e := envelope(uint16(kind), body, seed, recipient, context, expiry)
		all[kind] = e
		must(verifyEnvelope(e) == 0, "fixture signature")
		out = append(out, M{"name": fmt.Sprintf("signed_kind_%02d", kind), "kind": ref("kinds", kind), "scope": "canonical fixture and signature; not runtime admission", "signing_seed_hex": hex(seed), "body_hex": hex(body), "header_hex": hex(e[:140]), "signed_bytes_hex": hex(cat([]byte(domain), e[:len(e)-64])), "signature_hex": hex(e[len(e)-64:]), "envelope_hex": hex(e), "sha256_hex": hex(hash(e)), "expect": "accept"})
	}
	ack := all[8][140 : len(all[8])-64]
	must(bytes.Equal(ack[:32], hash(all[12])), "ACK must hash the HEARTBEAT envelope")
	must(binary.BigEndian.Uint16(ack[56:58]) == 12 && bytes.Equal(ack[58:66], all[12][156:164]), "heartbeat ACK operation/counter")
	return out, all
}

func main() {
	spec, err := os.ReadFile("../../protocol/v1.md")
	check(err)
	part := strings.Split(strings.Split(string(spec), "<!-- code-table -->")[1], "<!-- /code-table -->")[0]
	check(json.Unmarshal([]byte(strings.Split(part, "```")[1][5:]), &tables))
	envelopes, all := fixtureEnvelopes()
	output := M{"protocol_version": 1, "notice": "Public fixed test inputs. Signature fixtures do not execute protocol state; PROOF handshake hash is a placeholder, full NK transcripts belong to T02.", "known_answer": knownAnswers(), "derivations": derivations(), "envelopes": envelopes, "wallet": walletVectors(), "negative": negativeVectors(all), "key_files": keyFileVectors(), "operations": operationVectors(all), "objects": objectVectors(), "time": timeVectors()}
	output["frames"] = frameVectors(all)
	output["quest_pagination"] = questPaginationVectors()
	output["prologue"] = M{"player_hex": hex(player), "land_hex": hex(land), "sid_hex": hex(sid), "card_sha256_hex": hex(hash(all[7])), "bytes_hex": hex(cat([]byte("linked-realms/connect/noise/v1\x00"), u16(1), player, land, sid, hash(all[7])))}
	encoded, err := json.MarshalIndent(output, "", "  ")
	check(err)
	encoded = append(encoded, '\n')
	check(os.MkdirAll("../../protocol/vectors", 0755))
	check(os.WriteFile("../../protocol/vectors/v1.json", encoded, 0644))
	fmt.Printf("generated v1.json (%d bytes), assertions passed\n", len(encoded))
}
