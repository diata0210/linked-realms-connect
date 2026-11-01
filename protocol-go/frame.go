package protocol

import (
	"bytes"
	"encoding/binary"
	"strings"
)

const MaxRecord = 32768
const FrameHeaderSize = 31

type Frame struct {
	// HubAuthored is authenticated caller context, never inferred from payload bytes.
	HubAuthored bool
	Type        byte
	Route       [16]byte
	Sequence    uint64
	Payload     []byte
}

func DecodeFrame(b []byte, route [16]byte, next uint64, options ...DecodeOptions) (*Frame, error) {
	if len(options) > 1 {
		return nil, Malformed
	}
	var opts DecodeOptions
	if len(options) == 1 {
		opts = options[0]
	}
	if len(b) == 0 || len(b) > MaxRecord {
		return nil, Malformed
	}
	f := &Frame{Type: b[0], HubAuthored: opts.HubAuthored}
	if f.Type == 0 {
		if _, err := DecodeEnvelope(b[1:], opts); err != nil {
			return nil, err
		}
		f.Payload = append([]byte(nil), b[1:]...)
		return f, nil
	}
	if f.Type != 1 && f.Type != 2 || len(b) < 31 {
		return nil, Malformed
	}
	if binary.BigEndian.Uint16(b[1:3]) != 1 {
		return nil, UnsupportedVersion
	}
	copy(f.Route[:], b[3:19])
	if f.Route != route {
		return nil, Malformed
	}
	f.Sequence = binary.BigEndian.Uint64(b[19:27])
	n := binary.BigEndian.Uint32(b[27:31])
	if uint64(n)+31 != uint64(len(b)) {
		return nil, Malformed
	}
	if f.Type == 1 {
		if f.Sequence != 0 || n > 4096 || n < 36 {
			return nil, Malformed
		}
		m := binary.BigEndian.Uint32(b[63:67])
		if uint64(m)+36 != uint64(n) {
			return nil, Malformed
		}
	} else {
		if n < 16 {
			return nil, Malformed
		}
		if f.Sequence != next {
			return nil, Replay
		}
	}
	f.Payload = append([]byte(nil), b[31:]...)
	return f, nil
}
func FrameHeader(typ byte, route [16]byte, seq uint64, n int) ([]byte, error) {
	if (typ != 1 && typ != 2) || n < 0 || n > 32737 || typ == 1 && (seq != 0 || n > 4096) {
		return nil, Malformed
	}
	b := []byte{typ, 0, 1}
	b = append(b, route[:]...)
	b = binary.BigEndian.AppendUint64(b, seq)
	return binary.BigEndian.AppendUint32(b, uint32(n)), nil
}
func (f *Frame) Encode() ([]byte, error) {
	if f.Type == 0 {
		b := append([]byte{0}, f.Payload...)
		_, err := DecodeFrame(b, f.Route, 0, DecodeOptions{HubAuthored: f.HubAuthored})
		return b, err
	}
	h, err := FrameHeader(f.Type, f.Route, f.Sequence, len(f.Payload))
	if err != nil {
		return nil, err
	}
	b := append(h, f.Payload...)
	_, err = DecodeFrame(b, f.Route, f.Sequence)
	return b, err
}

var operations = map[uint16][]field{
	1: fields("envelope:blob:32711"), 2: fields("random:id"), 3: fields("random:id"), 4: fields("reason:u16"),
	5: fields("method:text:8 path:text:2048 headers:list.header:16 total:u32"),
	6: fields("offset:u32 final:bool bytes:blob:16384"),
	7: fields("status:u16 headers:list.header:16 total:u32"),
	8: fields("offset:u32 final:bool bytes:blob:16384"), 9: fields("path:text:2048"), 10: {},
	11: fields("message_id:u32 binary:bool offset:u32 total:u32 final:bool bytes:blob:16384"), 12: fields("reason:u16"),
}

type Operation struct {
	Code   uint16
	Stream uint32
	Body   Values
}

func DecodeOperation(b []byte) (*Operation, error) {
	if len(b) < 6 || len(b) > 32721 {
		return nil, Malformed
	}
	op := &Operation{Code: binary.BigEndian.Uint16(b[:2]), Stream: binary.BigEndian.Uint32(b[2:6])}
	s, ok := operations[op.Code]
	if !ok {
		return nil, Malformed
	}
	r := reader{b: b[6:]}
	op.Body = r.object(s)
	if err := r.done(); err != nil {
		return nil, err
	}
	return op, op.validate()
}
func (o *Operation) Encode() ([]byte, error) {
	s, ok := operations[o.Code]
	if !ok {
		return nil, Malformed
	}
	b := binary.BigEndian.AppendUint16(nil, o.Code)
	b = binary.BigEndian.AppendUint32(b, o.Stream)
	b, err := putObject(b, s, o.Body)
	if err != nil {
		return nil, err
	}
	if len(b) > 32721 {
		return nil, Malformed
	}
	return b, o.validate()
}
func (o *Operation) validate() error {
	if o.Code <= 4 && o.Stream != 0 || o.Code >= 5 && (o.Stream == 0 || o.Stream%2 == 0) {
		return Malformed
	}
	v := o.Body
	if x, ok := v["reason"]; ok && x.(uint64) > 16 {
		return Malformed
	}
	if o.Code == 1 {
		_, err := DecodeEnvelope(binaryField(v, "envelope"), DecodeOptions{})
		return err
	}
	if o.Code == 5 {
		m := v["method"].(string)
		if m == "" {
			return Malformed
		}
		for _, c := range m {
			if c < 'A' || c > 'Z' {
				return Malformed
			}
		}
		if number(v, "total") > 65536 {
			return Malformed
		}
	}
	if o.Code == 7 {
		if number(v, "status") < 100 || number(v, "status") > 599 || number(v, "total") > 524288 {
			return Malformed
		}
	}
	if path, ok := v["path"]; ok {
		if err := ValidatePath(path.(string)); err != nil {
			return err
		}
	}
	if hs, ok := v["headers"]; ok {
		prev := ""
		n := 2
		for _, x := range hs.([]any) {
			h := x.(Values)
			name := h["name"].(string)
			value := h["value"].(string)
			n += 8 + len(name) + len(value)
			if name <= prev || strings.ToLower(name) != name || strings.ContainsAny(value, "\r\n") {
				return Malformed
			}
			for _, c := range name {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
					return Malformed
				}
			}
			prev = name
		}
		if n > 4096 {
			return Malformed
		}
	}
	if o.Code == 6 || o.Code == 8 || o.Code == 11 {
		n := uint64(len(binaryField(v, "bytes")))
		if n == 0 && number(v, "final") == 0 || number(v, "offset")+n > 1<<32-1 {
			return Malformed
		}
		if o.Code == 11 {
			end := number(v, "offset") + n
			if end > number(v, "total") || number(v, "total") > 1048576 || (number(v, "final") == 1) != (end == number(v, "total")) {
				return Malformed
			}
		}
	}
	return nil
}

// ValidatePath rejects normalization ambiguity. Route-specific matchmaking and
// reservation allowlists are a bridge responsibility, after this syntax check.
func ValidatePath(s string) error {
	if s == "" || len(s) > 2048 || s[0] != '/' || strings.HasPrefix(s, "//") || strings.ContainsAny(s, "\\\r\n#\x00") {
		return Malformed
	}
	lower := strings.ToLower(s)
	for _, bad := range []string{"%", "/../", "/./"} {
		if strings.Contains(lower, bad) {
			return Malformed
		}
	}
	if strings.HasSuffix(s, "/..") || strings.HasSuffix(s, "/.") {
		return Malformed
	}
	return nil
}
func Prologue(player, land [32]byte, sid [16]byte, cardHash [32]byte) []byte {
	b := append([]byte("linked-realms/connect/noise/v1\x00"), 0, 1)
	b = append(b, player[:]...)
	b = append(b, land[:]...)
	b = append(b, sid[:]...)
	return append(b, cardHash[:]...)
}
func CheckHandshakeCard(f *Frame, hash [32]byte) error {
	if f.Type != 1 || len(f.Payload) < 36 || !bytes.Equal(f.Payload[:32], hash[:]) {
		return Malformed
	}
	return nil
}
