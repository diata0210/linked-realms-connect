package protocol

import (
	"bytes"
	"encoding/base64"
	_ "golang.org/x/image/webp"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"strings"
)

func validateProfile(v Values) error {
	b, err := putObject(nil, structures["profile"], v)
	if err != nil || len(b) > 9216 {
		return Malformed
	}
	if err = VerifySignature(binaryField(v, "player_key"), signed(ProfileDomain, b[:len(b)-64]), binaryField(v, "signature")); err != nil {
		return err
	}
	a := binaryField(v, "avatar")
	switch number(v, "avatar_kind") {
	case 0:
		// v1 ships only the required default preset; adding presets requires an
		// explicit shared allowlist, not accepting arbitrary remote resource names.
		if string(a) != "default" {
			return Malformed
		}
	case 1:
		if len(a) < 2 || len(a) > 8193 || a[0] > 2 {
			return Malformed
		}
		format := []string{"png", "jpeg", "webp"}[a[0]]
		cfg, got, err := image.DecodeConfig(bytes.NewReader(a[1:]))
		if err != nil || got != format || cfg.Width < 1 || cfg.Height < 1 || cfg.Width > 128 || cfg.Height > 128 {
			return Malformed
		}
		if _, got, err = image.Decode(bytes.NewReader(a[1:])); err != nil || got != format {
			return Malformed
		}
	default:
		return Malformed
	}
	return nil
}
func DecodeProfile(b []byte) (Values, error) {
	if len(b) > 9216 {
		return nil, Malformed
	}
	r := reader{b: b}
	v := r.object(structures["profile"])
	if err := r.done(); err != nil {
		return nil, err
	}
	if err := validateProfile(v); err != nil {
		return nil, err
	}
	return v, nil
}
func EncodeProfile(v Values) ([]byte, error) {
	if err := validateProfile(v); err != nil {
		return nil, err
	}
	return putObject(nil, structures["profile"], v)
}
func DecodeInvite(b []byte) (Values, error) {
	if len(b) > 2048 || len(b) < 1 {
		return nil, Malformed
	}
	if b[0] != 1 {
		return nil, UnsupportedVersion
	}
	r := reader{b: b}
	v := r.object(structures["invite"])
	if err := r.done(); err != nil {
		return nil, err
	}
	if err := VerifySignature(binaryField(v, "land_key"), signed(InviteDomain, b[:len(b)-64]), binaryField(v, "signature")); err != nil {
		return nil, err
	}
	if err := validateEndpoints(v["hubs"]); err != nil {
		return nil, err
	}
	return v, nil
}
func EncodeInvite(v Values) ([]byte, error) {
	b, err := putObject(nil, structures["invite"], v)
	if err != nil {
		return nil, err
	}
	_, err = DecodeInvite(b)
	return b, err
}
func DecodeInviteURL(s string, now uint64) (Values, error) {
	const prefix = "linkedrealms://invite/"
	if len(s) > 3072 || !strings.HasPrefix(s, prefix) {
		return nil, Malformed
	}
	x := s[len(prefix):]
	b, err := base64.RawURLEncoding.Strict().DecodeString(x)
	if err != nil || base64.RawURLEncoding.EncodeToString(b) != x {
		return nil, Malformed
	}
	v, err := DecodeInvite(b)
	if err != nil {
		return nil, err
	}
	if now >= number(v, "expires_at") {
		return nil, Expired
	}
	return v, nil
}
func EncodeInviteURL(v Values) (string, error) {
	b, err := EncodeInvite(v)
	if err != nil {
		return "", err
	}
	return "linkedrealms://invite/" + base64.RawURLEncoding.EncodeToString(b), nil
}

// Revision is a caller-persisted high-water mark. Equal bytes are idempotent;
// callers must durably store the returned mark before using the object.
type Revision struct {
	Number uint64
	Hash   [32]byte
}

func CheckRevision(old *Revision, next uint64, b []byte) (Revision, error) {
	r := Revision{next, Hash(b)}
	if old != nil && (next < old.Number || next == old.Number && r.Hash != old.Hash) {
		return Revision{}, StaleCard
	}
	return r, nil
}
