// Package noisesession is agent-only. The public protocol module and Hub must
// never import it. All handshakes and AEAD operations use pinned flynn/noise.
package noisesession

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	protocol "github.com/diata0210/linked-realms-connect/protocol-go"
	"github.com/flynn/noise"
	"io"
	"sync"
)

const Suite = "Noise_NK_25519_ChaChaPoly_SHA256"
const MaxRecords = 1 << 20
const MaxBytes = 1 << 30

type Config struct {
	Initiator    bool
	Player, Land [32]byte
	SID, Route   [16]byte
	CardHash     [32]byte
	PeerStatic   []byte
	StaticKey    noise.DHKey
}
type Session struct {
	mu                       sync.Mutex
	hs                       *noise.HandshakeState
	send, receive            *noise.CipherState
	initiator                bool
	route                    [16]byte
	card                     [32]byte
	step                     int
	closed                   bool
	hash                     []byte
	sentBytes, receivedBytes uint64
}

// GenerateStatic must be called anew for each Land process boot. Never persist it.
func GenerateStatic() (noise.DHKey, error) { return noise.DH25519.GenerateKeypair(rand.Reader) }
func New(c Config) (*Session, error)       { return newSession(c, rand.Reader) }

// Deterministic randomness is restricted to package tests, never exported.
func newSession(c Config, random io.Reader) (*Session, error) {
	if c.Initiator {
		if err := validDH(c.PeerStatic); err != nil {
			return nil, err
		}
	} else {
		k, err := ecdh.X25519().NewPrivateKey(c.StaticKey.Private)
		if err != nil || !bytes.Equal(k.PublicKey().Bytes(), c.StaticKey.Public) {
			return nil, protocol.BadSignature
		}
	}
	hs, err := noise.NewHandshakeState(noise.Config{CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256), Pattern: noise.HandshakeNK, Initiator: c.Initiator, Random: random, Prologue: protocol.Prologue(c.Player, c.Land, c.SID, c.CardHash), StaticKeypair: c.StaticKey, PeerStatic: append([]byte(nil), c.PeerStatic...)})
	if err != nil {
		return nil, err
	}
	return &Session{hs: hs, initiator: c.Initiator, route: c.Route, card: c.CardHash}, nil
}
func validDH(pub []byte) error {
	// X25519 rejects every low-order input through an all-zero shared secret.
	p, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return protocol.BadSignature
	}
	var private [32]byte
	private[0] = 9
	k, err := ecdh.X25519().NewPrivateKey(private[:])
	if err != nil {
		return err
	}
	if _, err = k.ECDH(p); err != nil {
		return protocol.BadSignature
	}
	return nil
}
func (s *Session) fail(err error) error {
	s.closed = true
	s.hs = nil
	s.send = nil
	s.receive = nil
	clear(s.hash)
	s.hash = nil
	return err
}
func (s *Session) split(a, b *noise.CipherState) {
	if a == nil || b == nil {
		return
	}
	s.hash = append([]byte(nil), s.hs.ChannelBinding()...)
	if s.initiator {
		s.send, s.receive = a, b
	} else {
		s.send, s.receive = b, a
	}
	s.hs = nil
}

// WriteHandshake emits exactly one empty-payload NK message in each direction.
func (s *Session) WriteHandshake() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.hs == nil || s.initiator && s.step != 0 || !s.initiator && s.step != 1 {
		return nil, s.fail(protocol.Malformed)
	}
	m, a, b, err := s.hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, s.fail(err)
	}
	s.step++
	s.split(a, b)
	payload := append([]byte(nil), s.card[:]...)
	payload = binary.BigEndian.AppendUint32(payload, uint32(len(m)))
	payload = append(payload, m...)
	return (&protocol.Frame{Type: 1, Route: s.route, Payload: payload}).Encode()
}
func (s *Session) ReadHandshake(record []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.hs == nil || s.initiator && s.step != 1 || !s.initiator && s.step != 0 {
		return s.fail(protocol.Malformed)
	}
	f, err := protocol.DecodeFrame(record, s.route, 0)
	if err != nil {
		return s.fail(err)
	}
	if err = protocol.CheckHandshakeCard(f, s.card); err != nil {
		return s.fail(err)
	}
	m := f.Payload[36:]
	// NK messages are e (32) plus the empty payload's tag (16).
	if len(m) != 48 {
		return s.fail(protocol.Malformed)
	}
	if err = validDH(m[:32]); err != nil {
		return s.fail(err)
	}
	payload, a, b, err := s.hs.ReadMessage(nil, m)
	if err != nil {
		return s.fail(protocol.BadSignature)
	}
	if len(payload) != 0 {
		return s.fail(protocol.Malformed)
	}
	s.step++
	s.split(a, b)
	return nil
}
func (s *Session) HandshakeHash() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.send == nil {
		return nil, protocol.Malformed
	}
	return append([]byte(nil), s.hash...), nil
}
func (s *Session) Encrypt(plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.send == nil {
		return nil, s.fail(protocol.Malformed)
	}
	n := len(plaintext) + 16
	if n > 32737 || s.send.Nonce()+1 >= MaxRecords || s.sentBytes+uint64(n) >= MaxBytes {
		return nil, s.fail(protocol.Busy)
	}
	header, err := protocol.FrameHeader(2, s.route, s.send.Nonce(), n)
	if err != nil {
		return nil, s.fail(err)
	}
	ciphertext, err := s.send.Encrypt(nil, header, plaintext)
	if err != nil {
		return nil, s.fail(err)
	}
	s.sentBytes += uint64(n)
	return append(header, ciphertext...), nil
}
func (s *Session) Decrypt(record []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.receive == nil {
		return nil, s.fail(protocol.Malformed)
	}
	f, err := protocol.DecodeFrame(record, s.route, s.receive.Nonce())
	if err != nil {
		return nil, s.fail(err)
	}
	if f.Type != 2 {
		return nil, s.fail(protocol.Malformed)
	}
	if s.receive.Nonce()+1 >= MaxRecords || s.receivedBytes+uint64(len(f.Payload)) >= MaxBytes {
		return nil, s.fail(protocol.Busy)
	}
	p, err := s.receive.Decrypt(nil, record[:31], f.Payload)
	if err != nil {
		return nil, s.fail(protocol.BadSignature)
	}
	s.receivedBytes += uint64(len(f.Payload))
	return p, nil
}
func (s *Session) Close() { s.mu.Lock(); defer s.mu.Unlock(); s.fail(protocol.OrderlyClose) }
