package protocol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fixtures(t testing.TB) map[string]json.RawMessage {
	t.Helper()
	b, err := os.ReadFile("../protocol/vectors/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]json.RawMessage
	if err = json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}
func firstEnvelope(t testing.TB) []byte {
	var a []struct {
		Hex string `json:"envelope_hex"`
	}
	json.Unmarshal(fixtures(t)["envelopes"], &a)
	b, err := hex.DecodeString(a[0].Hex)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestCodeTables(t *testing.T) {
	b, err := os.ReadFile("../protocol/v1.md")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("(?s)<!-- code-table -->\\s*```json\\s*(.*?)\\s*```").FindSubmatch(b)
	if len(m) != 2 {
		t.Fatal("missing table")
	}
	var spec map[string][][2]any
	json.Unmarshal(m[1], &spec)
	for name, rows := range map[string][][2]any{"kinds": Kinds, "ops": Ops, "errors": Errors} {
		start := 1
		if name == "errors" {
			start = 0
		}
		if err = ValidateTable(rows, start); err != nil {
			t.Fatal(err)
		}
		x, _ := json.Marshal(rows)
		y, _ := json.Marshal(spec[name])
		if !bytes.Equal(x, y) {
			t.Fatal(name)
		}
	}
}
func TestReplayClockCapacityAndRace(t *testing.T) {
	e, err := DecodeEnvelope(firstEnvelope(t), DecodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	e.IssuedAt = 1120
	e.ExpiresAt = 1180
	c := NewReplayCache(1)
	mono := time.Now()
	c.clock = func() time.Time { return mono }
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.Accept(e, 1000); err == nil {
				accepted.Add(1)
			} else if err != Replay {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatal("non-atomic replay acceptance")
	}
	other := *e
	other.Nonce[0] ^= 1
	if c.Accept(&other, 1000) != Busy {
		t.Fatal("live nonce evicted")
	}
	mono = mono.Add(299 * time.Second)
	if c.Accept(&other, 1000) != Busy {
		t.Fatal("early eviction")
	}
	mono = mono.Add(time.Second)
	if c.Accept(&other, 1000) != nil {
		t.Fatal("monotonic expiry")
	}
	if _, err := CheckTime(^uint64(0)-60, ^uint64(0), ^uint64(0)-180, 60); err != nil {
		t.Fatal(err)
	}
}
func TestBindingRevisionAndStrictSignatures(t *testing.T) {
	e, err := DecodeEnvelope(firstEnvelope(t), DecodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	w := Binding{e.Sender, e.Recipient, e.Context, e.Kind}
	if e.CheckBinding(w) != nil {
		t.Fatal("binding")
	}
	w.Context[0] ^= 1
	if e.CheckBinding(w) != PolicyChanged {
		t.Fatal("context accepted")
	}
	r, _ := CheckRevision(nil, 2, []byte{1})
	if _, err = CheckRevision(&r, 1, []byte{1}); err != StaleCard {
		t.Fatal(err)
	}
	if _, err = CheckRevision(&r, 2, []byte{2}); err != StaleCard {
		t.Fatal(err)
	}
	for _, point := range [][]byte{make([]byte, 32), append([]byte{1}, make([]byte, 31)...), bytes.Repeat([]byte{255}, 32)} {
		if StrictPoint(point) {
			t.Fatal("invalid point accepted")
		}
	}
	seed := make([]byte, 32)
	key := ed25519.NewKeyFromSeed(seed)
	message := []byte("strict")
	sig := ed25519.Sign(key, message)
	if VerifySignature(key.Public().(ed25519.PublicKey), message, sig) != nil {
		t.Fatal("valid rejected")
	}
	sig[63] |= 0x80
	if VerifySignature(key.Public().(ed25519.PublicKey), message, sig) != BadSignature {
		t.Fatal("noncanonical S")
	}
}
func TestCanonicalBodiesAndOrigins(t *testing.T) {
	for _, origin := range []string{"https://hub.example", "https://[2001:db8::1]:8443", "https://192.0.2.1"} {
		if ValidateOrigin(origin) != nil {
			t.Fatal(origin)
		}
	}
	for _, origin := range []string{"https://HUB.example", "https://hub.example/", "https://hub.example:443", "https://01.2.3.4", "https://hub.example?", "https://[2001:0db8::1]", "https://user@host", "https://host:0443"} {
		if ValidateOrigin(origin) == nil {
			t.Fatal(origin)
		}
	}
	for kind := uint16(1); kind <= 32; kind++ {
		if _, ok := bodies[kind]; !ok {
			t.Fatal(kind)
		}
	}
	for _, typ := range []string{"bool", "text", "blob"} {
		if _, err := DecodePrimitive([]byte{255, 255, 255, 255}, typ, 32); err == nil {
			t.Fatal(typ)
		}
	}
}
func FuzzEnvelope(f *testing.F) {
	f.Add(firstEnvelope(f))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := DecodeEnvelope(b, DecodeOptions{})
		if err == nil {
			x, err := e.Encode()
			if err != nil || !bytes.Equal(x, b) {
				t.Fatal("round trip")
			}
		}
	})
}
func FuzzFrame(f *testing.F) {
	f.Add([]byte{2})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = DecodeFrame(b, [16]byte{}, 0) })
}
func FuzzProfile(f *testing.F) {
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = DecodeProfile(b) })
}
func FuzzInvite(f *testing.F) {
	f.Add("linkedrealms://invite/")
	f.Fuzz(func(t *testing.T, s string) { _, _ = DecodeInviteURL(s, 0) })
}
func FuzzOperation(f *testing.F) {
	f.Add([]byte{0, 2, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = DecodeOperation(b) })
}
func FuzzPath(f *testing.F) {
	f.Add("/matchmake/joinOrCreate/land")
	f.Fuzz(func(t *testing.T, s string) { _ = ValidatePath(s) })
}

func FuzzCard(f *testing.F) {
	var envelopes []struct {
		Hex string `json:"envelope_hex"`
	}
	if err := json.Unmarshal(fixtures(f)["envelopes"], &envelopes); err != nil {
		f.Fatal(err)
	}
	b, err := hex.DecodeString(envelopes[6].Hex)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := DecodeEnvelope(b, DecodeOptions{})
		if err == nil && e.Kind == KindCard {
			encoded, err := e.Encode()
			if err != nil || !bytes.Equal(encoded, b) {
				t.Fatal("card round trip")
			}
		}
	})
}

func FuzzChunk(f *testing.F) {
	var operations []struct {
		Hex string `json:"plaintext_hex"`
	}
	if err := json.Unmarshal(fixtures(f)["operations"], &operations); err != nil {
		f.Fatal(err)
	}
	for _, i := range []int{5, 7, 10} {
		b, err := hex.DecodeString(operations[i].Hex)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		op, err := DecodeOperation(b)
		if err == nil {
			encoded, err := op.Encode()
			if err != nil || !bytes.Equal(encoded, b) {
				t.Fatal("chunk round trip")
			}
		}
	})
}
