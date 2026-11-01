// Package protocol implements the canonical public Linked Realms v1 wire contract.
// It contains no agent key storage or Noise dependency. Decode verifies signatures;
// callers must separately enforce peer binding, freshness and application state.
package protocol

import (
	"encoding/binary"
	"strings"
	"unicode/utf8"
)

// Values contains schema fields. Integers are uint64, binary fields []byte,
// text fields string, structures Values, lists []any; absent optionals are nil.
// Encoders reject missing/unknown fields and out-of-range values.
type Values map[string]any

type reader struct {
	b   []byte
	pos int
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b)-r.pos {
		r.err = Malformed
		return nil
	}
	b := r.b[r.pos : r.pos+n]
	r.pos += n
	return b
}
func (r *reader) num(n int) uint64 {
	b := r.take(n)
	if b == nil {
		return 0
	}
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}
func (r *reader) blob(max int) []byte {
	n := r.num(4)
	if n > uint64(max) || n > uint64(len(r.b)-r.pos) {
		r.err = Malformed
		return nil
	}
	return append([]byte(nil), r.take(int(n))...)
}
func (r *reader) done() error {
	if r.err != nil {
		return r.err
	}
	if r.pos != len(r.b) {
		return Malformed
	}
	return nil
}
func (r *reader) boolean() uint64 {
	v := r.num(1)
	if v > 1 {
		r.err = Malformed
	}
	return v
}

type field struct {
	name, typ string
	max       int
}

func fields(s string) []field {
	var out []field
	for _, item := range strings.Fields(s) {
		p := strings.Split(item, ":")
		f := field{name: p[0], typ: p[1]}
		if len(p) == 3 {
			for _, c := range p[2] {
				f.max = f.max*10 + int(c-'0')
			}
		}
		out = append(out, f)
	}
	return out
}

var structures = map[string][]field{
	"endpoint": fields("origin:text:192 hub_key:key"),
	"tuple":    fields("quest_id:id poster_key:key"),
	"entry":    fields("card:blob:4096 online:bool observed_at:u64"),
	"item":     fields("item_id:text:64 quantity:u64"),
	"header":   fields("name:text:64 value:text:512"),
	"profile":  fields("player_key:key revision:u64 display_name:text:32 avatar_kind:u8 avatar:blob:8193 signature:sig"),
	"invite":   fields("version:u8 land_key:key hubs:list.endpoint:8 code:key expires_at:u64 signature:sig"),
}
var bodies = map[uint16][]field{
	1:  {},
	2:  fields("origin:text:192 versions:list.u16:1 max_frame:u32 max_card:u32 max_routes_per_land:u32 max_streams:u32"),
	3:  fields("land:?key cursor:?key limit:u16"),
	4:  fields("next:?key entries:list.entry:64"),
	5:  fields("card:blob:4096"),
	6:  fields("card_hash:key revision:u64"),
	7:  fields("land_key:key name:text:64 description:text:512 noise_key:key door_mode:u8 hubs:list.endpoint:8 current_players:u16 max_players:u16 protocol_version:u16 revision:u64 policy_revision:u64 allow_guest:bool"),
	8:  fields("operation:u16 revision:u64"),
	9:  fields("connection:id challenge:key role:u8"),
	10: fields("challenge_hash:key hub_boot:id role:u8 land:?key"),
	11: fields("connection:id"),
	12: fields("connection:id counter:u64"),
	13: fields("land:key sid:id card_hash:key"),
	14: fields("route:id player:key sid:id card_hash:key peer_ip:text:45"),
	15: fields("route:id sid:id"),
	16: fields("route:id reason:u16"),
	17: fields("reason:u16 retry_after:u32"),
	18: fields("deadline:u64"),
	19: fields("land:key sid:id key_class:u8 source_land:?key arrival_gate:u8 profile:?profile wallet:?blob:64"),
	20: fields("greeting_hash:key challenge:key boot:id policy_revision:u64 deadline:u64"),
	21: fields("challenge_hash:key challenge:key handshake_hash:key boot:id sid:id invite_code:?key"),
	22: fields("proof_hash:key seat:id player:key land:key sid:id generation:u64 policy_revision:u64 deadline:u64"),
	23: fields("proof_hash:key reason:u16"),
	24: fields("policy_revision:u64 door_mode:u8 reason:u16"),
	25: fields("policy_revision:u64 door_mode:u8 reason:u16"),
	26: fields("quest_id:id poster_key:key poster_land:key title:text:96 description:text:512 items:list.item:8 gold_reward:u64 expires_at:u64 revision:u64"),
	27: fields("card:blob:2048"),
	28: fields("quest_id:id revision:u64"),
	29: fields("cursor:?tuple limit:u16"),
	30: fields("next:?tuple cards:list.card:64"),
	31: fields("quest_hash:key quest_id:id taker:key quantity:u64"),
	32: fields("accept_hash:key quest_id:id status:u8 fulfillment_id:id"),
}
var prefix = fields("request_hash:key hub_time:u64 hub_boot:id")

func schema(kind uint16, hub bool) ([]field, error) {
	s, ok := bodies[kind]
	if !ok {
		return nil, Malformed
	}
	if hub {
		s = append(append([]field{}, prefix...), s...)
	}
	return s, nil
}
func (r *reader) value(t string, max int) any {
	if strings.HasPrefix(t, "?") {
		if r.boolean() == 0 {
			return nil
		}
		return r.value(t[1:], max)
	}
	if strings.HasPrefix(t, "list.") {
		n := r.num(2)
		if n > uint64(max) || n > uint64(len(r.b)-r.pos) {
			r.err = Malformed
			return []any(nil)
		}
		a := make([]any, 0, int(n))
		for i := uint64(0); i < n && r.err == nil; i++ {
			a = append(a, r.value(t[5:], 0))
		}
		return a
	}
	switch t {
	case "u8":
		return r.num(1)
	case "bool":
		return r.boolean()
	case "u16":
		return r.num(2)
	case "u32":
		return r.num(4)
	case "u64":
		return r.num(8)
	case "key":
		return append([]byte(nil), r.take(32)...)
	case "id":
		return append([]byte(nil), r.take(16)...)
	case "sig":
		return append([]byte(nil), r.take(64)...)
	case "card":
		return r.blob(2048)
	case "blob":
		return r.blob(max)
	case "text":
		b := r.blob(max)
		if !utf8.Valid(b) {
			r.err = Malformed
		}
		return string(b)
	default:
		s, ok := structures[t]
		if !ok {
			r.err = Malformed
			return nil
		}
		return r.object(s)
	}
}
func (r *reader) object(s []field) Values {
	v := Values{}
	for _, f := range s {
		v[f.name] = r.value(f.typ, f.max)
		if r.err != nil {
			break
		}
	}
	return v
}
func putValue(b []byte, t string, max int, v any) ([]byte, error) {
	if strings.HasPrefix(t, "?") {
		if v == nil {
			return append(b, 0), nil
		}
		return putValue(append(b, 1), t[1:], max, v)
	}
	if strings.HasPrefix(t, "list.") {
		a, ok := v.([]any)
		if !ok || len(a) > max {
			return nil, Malformed
		}
		b = binary.BigEndian.AppendUint16(b, uint16(len(a)))
		var err error
		for _, x := range a {
			b, err = putValue(b, t[5:], 0, x)
			if err != nil {
				return nil, err
			}
		}
		return b, nil
	}
	widths := map[string]int{"u8": 1, "bool": 1, "u16": 2, "u32": 4, "u64": 8}
	if n, ok := widths[t]; ok {
		x, ok := v.(uint64)
		if !ok || n < 8 && x >= uint64(1)<<(n*8) || t == "bool" && x > 1 {
			return nil, Malformed
		}
		for i := n - 1; i >= 0; i-- {
			b = append(b, byte(x>>uint(i*8)))
		}
		return b, nil
	}
	sizes := map[string]int{"key": 32, "id": 16, "sig": 64}
	if n, ok := sizes[t]; ok {
		x, ok := v.([]byte)
		if !ok || len(x) != n {
			return nil, Malformed
		}
		return append(b, x...), nil
	}
	if t == "blob" || t == "text" || t == "card" {
		var x []byte
		if t == "text" {
			s, ok := v.(string)
			if !ok || !utf8.ValidString(s) {
				return nil, Malformed
			}
			x = []byte(s)
		} else {
			var ok bool
			x, ok = v.([]byte)
			if !ok {
				return nil, Malformed
			}
		}
		if t == "card" {
			max = 2048
		}
		if len(x) > max {
			return nil, Malformed
		}
		return append(binary.BigEndian.AppendUint32(b, uint32(len(x))), x...), nil
	}
	s, ok := structures[t]
	if !ok {
		return nil, Malformed
	}
	o, ok := v.(Values)
	if !ok {
		return nil, Malformed
	}
	return putObject(b, s, o)
}
func putObject(b []byte, s []field, v Values) ([]byte, error) {
	if len(v) != len(s) {
		return nil, Malformed
	}
	for _, f := range s {
		x, ok := v[f.name]
		if !ok {
			return nil, Malformed
		}
		var err error
		b, err = putValue(b, f.typ, f.max, x)
		if err != nil {
			return nil, err
		}
	}
	return b, nil
}

// DecodePrimitive applies the same bounded readers used by message decoders.
func DecodePrimitive(b []byte, typ string, max int) (any, error) {
	r := reader{b: b}
	v := r.value(typ, max)
	return v, r.done()
}
