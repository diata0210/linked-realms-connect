package protocol

import (
	"bytes"
	"crypto/ed25519"
	"filippo.io/edwards25519"
)

const ControlDomain = "linked-realms/connect/control/v1\x00"
const ProfileDomain = "linked-realms/connect/profile/v1\x00"
const InviteDomain = "linked-realms/connect/invite/v1\x00"

// StrictPoint rejects noncanonical, identity, small-order and mixed-order points.
// Multiplying by 8 and then its inverse modulo the prime subgroup order projects
// onto that subgroup; equality proves the input had no torsion component.
func StrictPoint(b []byte) bool {
	p, err := new(edwards25519.Point).SetBytes(b)
	if err != nil || !bytes.Equal(p.Bytes(), b) || p.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return false
	}
	eightBytes := make([]byte, 32)
	eightBytes[0] = 8
	eight, _ := new(edwards25519.Scalar).SetCanonicalBytes(eightBytes)
	inv := new(edwards25519.Scalar).Invert(eight)
	q := new(edwards25519.Point).MultByCofactor(p)
	q.ScalarMult(inv, q)
	return q.Equal(p) == 1
}
func VerifySignature(key, message, signature []byte) error {
	if len(key) != 32 || len(signature) != 64 || !StrictPoint(key) || !StrictPoint(signature[:32]) {
		return BadSignature
	}
	if _, err := new(edwards25519.Scalar).SetCanonicalBytes(signature[32:]); err != nil {
		return BadSignature
	}
	if !ed25519.Verify(key, message, signature) {
		return BadSignature
	}
	return nil
}
func signed(domain string, b []byte) []byte { return append([]byte(domain), b...) }
