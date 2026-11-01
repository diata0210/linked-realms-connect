// Package identity derives agent-only private keys from the frozen v1 root seed.
// It does not implement key-file permissions, storage or CLI import/export (T08).
package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/btcsuite/btcd/btcec/v2"
	protocol "github.com/diata0210/linked-realms-connect/protocol-go"
	"io"
	"math/big"
	"strconv"
	"unicode/utf8"
)

type Derived struct{ Private, Chain, Public []byte }

func derive(seed []byte, secp bool, path []uint32) (Derived, error) {
	domain := "ed25519 seed"
	if secp {
		domain = "Bitcoin seed"
	}
	h := hmac.New(sha512.New, []byte(domain))
	h.Write(seed)
	sum := h.Sum(nil)
	key, chain := sum[:32], sum[32:]
	order := btcec.S256().Params().N
	valid := func(k []byte) bool { n := new(big.Int).SetBytes(k); return n.Sign() > 0 && n.Cmp(order) < 0 }
	if secp && !valid(key) {
		return Derived{}, errors.New("invalid fixed BIP32 master")
	}
	for _, index := range path {
		if index < 1<<31 {
			return Derived{}, errors.New("only hardened paths are allowed")
		}
		data := append([]byte{0}, key...)
		data = binary.BigEndian.AppendUint32(data, index)
		h = hmac.New(sha512.New, chain)
		h.Write(data)
		sum = h.Sum(nil)
		if secp {
			left := new(big.Int).SetBytes(sum[:32])
			if left.Cmp(order) >= 0 {
				return Derived{}, errors.New("invalid fixed BIP32 child")
			}
			left.Add(left, new(big.Int).SetBytes(key)).Mod(left, order)
			if left.Sign() == 0 {
				return Derived{}, errors.New("zero fixed BIP32 child")
			}
			key = left.FillBytes(make([]byte, 32))
		} else {
			key = append([]byte(nil), sum[:32]...)
		}
		chain = append([]byte(nil), sum[32:]...)
	}
	var pub []byte
	if secp {
		_, p := btcec.PrivKeyFromBytes(key)
		pub = p.SerializeCompressed()
	} else {
		pub = ed25519.NewKeyFromSeed(key).Public().(ed25519.PublicKey)
	}
	return Derived{append([]byte(nil), key...), append([]byte(nil), chain...), pub}, nil
}

// Derive applies only the three frozen profiles. Wallet curve selection belongs
// to C1; this function does not invent address or transaction rules.
func Derive(root []byte, profile string) (Derived, error) {
	if len(root) != 32 {
		return Derived{}, protocol.Malformed
	}
	switch profile {
	case "identity":
		return derive(root, false, []uint32{0x80000000, 0x80000000})
	case "wallet_A":
		return derive(root, true, []uint32{0x80000001, 0x80000000})
	case "wallet_B":
		return derive(root, false, []uint32{0x80000001, 0x80000000})
	}
	return Derived{}, protocol.Malformed
}

type KeyFile struct {
	Kind      string
	Seed      [32]byte
	Public    [32]byte
	CreatedAt uint64
}

// DecodeKeyFile checks bytes only; it grants no assurance about OS permissions.
func DecodeKeyFile(b []byte) (*KeyFile, error) {
	if len(b) > 2048 || !utf8.Valid(b) {
		return nil, protocol.Malformed
	}
	d := json.NewDecoder(bytes.NewReader(b))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return nil, protocol.Malformed
	}
	m := map[string]json.RawMessage{}
	for d.More() {
		t, err = d.Token()
		if err != nil {
			return nil, protocol.Malformed
		}
		k, ok := t.(string)
		if !ok || m[k] != nil {
			return nil, protocol.Malformed
		}
		var v json.RawMessage
		if d.Decode(&v) != nil {
			return nil, protocol.Malformed
		}
		m[k] = v
	}
	if t, err = d.Token(); err != nil || t != json.Delim('}') {
		return nil, protocol.Malformed
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, protocol.Malformed
	}
	if len(m) != 8 {
		return nil, protocol.Malformed
	}
	allowed := []string{"format", "version", "kind", "algorithm", "public_key", "seed", "created_at", "encryption"}
	for _, k := range allowed {
		if m[k] == nil {
			return nil, protocol.Malformed
		}
	}
	var version int
	if json.Unmarshal(m["version"], &version) != nil {
		return nil, protocol.Malformed
	}
	if version != 2 {
		return nil, protocol.UnsupportedVersion
	}
	s := map[string]string{}
	for _, k := range allowed {
		if k != "version" {
			var v string
			if json.Unmarshal(m[k], &v) != nil {
				return nil, protocol.Malformed
			}
			s[k] = v
		}
	}
	if s["format"] != "linked-realms-key" || s["algorithm"] != "Ed25519" || s["encryption"] != "none" || s["kind"] != "player" && s["kind"] != "land" && s["kind"] != "hub" {
		return nil, protocol.Malformed
	}
	n, err := strconv.ParseUint(s["created_at"], 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != s["created_at"] {
		return nil, protocol.Malformed
	}
	decode := func(s string) ([]byte, error) {
		b, e := base64.RawURLEncoding.Strict().DecodeString(s)
		if e != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != s {
			return nil, protocol.Malformed
		}
		return b, nil
	}
	seed, err := decode(s["seed"])
	if err != nil {
		return nil, err
	}
	pub, err := decode(s["public_key"])
	if err != nil {
		return nil, err
	}
	expected := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if s["kind"] != "hub" {
		derived, err := Derive(seed, "identity")
		if err != nil {
			return nil, err
		}
		expected = derived.Public
	}
	if !bytes.Equal(pub, expected) {
		return nil, protocol.BadSignature
	}
	k := &KeyFile{Kind: s["kind"], CreatedAt: n}
	copy(k.Seed[:], seed)
	copy(k.Public[:], pub)
	return k, nil
}
