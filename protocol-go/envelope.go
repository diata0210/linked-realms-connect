package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
)

const Version uint16 = 1
const MaxEnvelope = 512 * 1024

type Envelope struct {
	Kind                uint16
	Sender, Recipient   [32]byte
	Context             [16]byte
	Nonce               [32]byte
	IssuedAt, ExpiresAt uint64
	Body                Values
	Signature           [64]byte
	HubAuthored         bool
}

// DecodeOptions describes who authored ambiguous hop controls (ROUTE_CLOSE).
// Fixed Hub-only kinds are always prefixed. It does not authenticate a role.
type DecodeOptions struct{ HubAuthored bool }

func hubKind(k uint16) bool {
	switch k {
	case 2, 4, 6, 8, 9, 11, 14, 15, 17, 18, 30:
		return true
	}
	return false
}
func DecodeEnvelope(b []byte, opts DecodeOptions) (*Envelope, error) {
	if len(b) < 204 || len(b) > MaxEnvelope || string(b[:4]) != "LRC1" {
		return nil, Malformed
	}
	if binary.BigEndian.Uint16(b[4:6]) != Version {
		return nil, UnsupportedVersion
	}
	k := binary.BigEndian.Uint16(b[6:8])
	hub := hubKind(k) || opts.HubAuthored
	s, err := schema(k, hub)
	if err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(b[136:140])
	if uint64(n)+204 != uint64(len(b)) {
		return nil, Malformed
	}
	if err = VerifySignature(b[8:40], signed(ControlDomain, b[:len(b)-64]), b[len(b)-64:]); err != nil {
		return nil, err
	}
	e := &Envelope{Kind: k, HubAuthored: hub, IssuedAt: binary.BigEndian.Uint64(b[120:128]), ExpiresAt: binary.BigEndian.Uint64(b[128:136])}
	copy(e.Sender[:], b[8:40])
	copy(e.Recipient[:], b[40:72])
	copy(e.Context[:], b[72:88])
	copy(e.Nonce[:], b[88:120])
	copy(e.Signature[:], b[len(b)-64:])
	r := reader{b: b[140 : len(b)-64]}
	e.Body = r.object(s)
	if err = r.done(); err != nil {
		return nil, err
	}
	if err = e.validate(len(b)); err != nil {
		return nil, err
	}
	return e, nil
}
func (e *Envelope) unsigned() ([]byte, error) {
	s, err := schema(e.Kind, hubKind(e.Kind) || e.HubAuthored)
	if err != nil {
		return nil, err
	}
	body, err := putObject(nil, s, e.Body)
	if err != nil {
		return nil, err
	}
	if len(body) > MaxEnvelope-204 {
		return nil, Malformed
	}
	if err = e.validate(len(body) + 204); err != nil {
		return nil, err
	}
	b := append([]byte("LRC1"), 0, 1)
	b = binary.BigEndian.AppendUint16(b, e.Kind)
	b = append(b, e.Sender[:]...)
	b = append(b, e.Recipient[:]...)
	b = append(b, e.Context[:]...)
	b = append(b, e.Nonce[:]...)
	b = binary.BigEndian.AppendUint64(b, e.IssuedAt)
	b = binary.BigEndian.AppendUint64(b, e.ExpiresAt)
	b = binary.BigEndian.AppendUint32(b, uint32(len(body)))
	return append(b, body...), nil
}

// Encode never repairs malformed fields or silently signs a modified object.
func (e *Envelope) Encode() ([]byte, error) {
	b, err := e.unsigned()
	if err != nil {
		return nil, err
	}
	if err = VerifySignature(e.Sender[:], signed(ControlDomain, b), e.Signature[:]); err != nil {
		return nil, err
	}
	return append(b, e.Signature[:]...), nil
}

// Sign signs a schema-checked envelope. Executable agent APIs must expose fixed
// operations, not this low-level protocol primitive. Nonces come from the OS RNG.
func (e *Envelope) Sign(key ed25519.PrivateKey) error {
	if len(key) != 64 {
		return BadSignature
	}
	copy(e.Sender[:], key.Public().(ed25519.PublicKey))
	if _, err := rand.Read(e.Nonce[:]); err != nil {
		return err
	}
	b, err := e.unsigned()
	if err != nil {
		return err
	}
	copy(e.Signature[:], ed25519.Sign(key, signed(ControlDomain, b)))
	return nil
}
func Hash(b []byte) [32]byte { return sha256.Sum256(b) }

type Binding struct {
	Sender, Recipient [32]byte
	Context           [16]byte
	Kind              uint16
}

func (e *Envelope) CheckBinding(w Binding) error {
	if e.Sender != w.Sender || e.Recipient != w.Recipient {
		return BadSignature
	}
	if e.Context != w.Context {
		return PolicyChanged
	}
	if e.Kind != w.Kind {
		return Malformed
	}
	return nil
}
func zero(b []byte) bool                    { return bytes.Equal(b, make([]byte, len(b))) }
func number(v Values, k string) uint64      { x, _ := v[k].(uint64); return x }
func binaryField(v Values, k string) []byte { x, _ := v[k].([]byte); return x }
