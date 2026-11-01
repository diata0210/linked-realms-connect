package main

import "bytes"

// Canonical phase-2 fixtures only; these do not execute a Hub query/store.
func questPaginationVectors() []M {
	lowSeed, highSeed := playerSeed, landSeed
	if bytes.Compare(pub(lowSeed), pub(highSeed)) > 0 {
		lowSeed, highSeed = highSeed, lowSeed
	}
	low, high := pub(lowSeed), pub(highSeed)
	laterID := bytes.Repeat([]byte{0x45}, 16)
	tuples := [][]byte{cat(route, low), cat(route, high), cat(laterID, low)}
	must(bytes.Compare(tuples[0], tuples[1]) < 0 && bytes.Compare(tuples[1], tuples[2]) < 0, "quest ID then poster order")
	var cards [][]byte
	for i, seed := range [][]byte{lowSeed, highSeed, lowSeed} {
		body := cat(tuples[i], land, txt("Pagination quest"), txt("shared ID fixture"), u16(1), txt("stone"), u64(1), u64(0), u64(issued+600), u64(1))
		card := envelope(26, body, seed, z(32), z(16), issued+600)
		must(verifyEnvelope(card) == 0 && bytes.Equal(card[8:40], tuples[i][16:]), "quest poster signature")
		cards = append(cards, card)
	}
	var out []M
	add := func(name string, kind uint16, body, seed, recipient []byte) []byte {
		e := envelope(kind, body, seed, recipient, boot, issued+60)
		must(verifyEnvelope(e) == 0, name)
		out = append(out, M{"name": name, "kind": ref("kinds", int(kind)), "scope": "canonical pagination and signature; not runtime query execution", "signing_seed_hex": hex(seed), "body_hex": hex(body), "envelope_hex": hex(e), "expect": "accept"})
		return e
	}
	absent := add("quest_query_cursor_absent", 29, cat([]byte{0}, u16(2)), playerSeed, hub)
	present := add("quest_query_cursor_present", 29, cat([]byte{1}, tuples[0], u16(2)), playerSeed, hub)
	out[1]["cursor"] = M{"quest_id_hex": hex(route), "poster_key_hex": hex(low)}

	// Two different posters sharing one quest ID fill the first page. A third
	// card remains, so next carries the complete final tuple, including poster.
	page := cat(hash(absent), u64(issued), boot, []byte{1}, tuples[1], u16(2), blob(cards[0]), blob(cards[1]))
	add("quest_page_shared_id_order", 30, page, hubSeed, player)
	out[2]["next"] = M{"quest_id_hex": hex(route), "poster_key_hex": hex(high)}
	out[2]["ordered_tuples_hex"] = []string{hex(tuples[0]), hex(tuples[1])}

	// Starting after the lower poster still returns the higher poster's same-ID
	// card, then the later quest ID even though its poster sorts lower.
	for _, tuple := range tuples[1:] {
		must(bytes.Compare(tuple, tuples[0]) > 0, "exclusive composite quest cursor")
	}
	page = cat(hash(present), u64(issued), boot, []byte{0}, u16(2), blob(cards[1]), blob(cards[2]))
	add("quest_page_after_cursor", 30, page, hubSeed, player)
	out[3]["ordered_tuples_hex"] = []string{hex(tuples[1]), hex(tuples[2])}
	return out
}
