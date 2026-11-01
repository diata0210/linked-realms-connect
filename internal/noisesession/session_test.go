package noisesession

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	protocol "github.com/diata0210/linked-realms-connect/protocol-go"
	"github.com/flynn/noise"
	"os"
	"path/filepath"
	"testing"
)

type nkFixture struct {
	Suite     string          `json:"suite"`
	Source    string          `json:"source"`
	Notice    string          `json:"notice"`
	Static    string          `json:"responder_static_private_hex"`
	Initiator string          `json:"initiator_ephemeral_private_hex"`
	Responder string          `json:"responder_ephemeral_private_hex"`
	Standard  []string        `json:"standard_messages_hex"`
	Project   *projectFixture `json:"project"`
}
type projectFixture struct {
	Prologue   string   `json:"prologue_hex"`
	Records    []string `json:"handshake_records_hex"`
	Hash       string   `json:"handshake_hash_hex"`
	Transport  []string `json:"transport_records_hex"`
	Plaintexts []string `json:"plaintexts_hex"`
	Negatives  []string `json:"negatives"`
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
func fixture(t *testing.T) nkFixture {
	t.Helper()
	b, err := os.ReadFile("../../protocol/vectors/nk-transcript.json")
	if err != nil {
		t.Fatal(err)
	}
	var f nkFixture
	if err = json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if f.Suite != Suite {
		t.Fatal("suite mismatch")
	}
	return f
}
func keypair(t *testing.T, private []byte) noise.DHKey {
	t.Helper()
	k, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return noise.DHKey{Private: private, Public: k.PublicKey().Bytes()}
}
func configs(t *testing.T, f nkFixture) (Config, Config) {
	t.Helper()
	b, err := os.ReadFile("../../protocol/vectors/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Prologue struct {
			Player string `json:"player_hex"`
			Land   string `json:"land_hex"`
			SID    string `json:"sid_hex"`
			Card   string `json:"card_sha256_hex"`
		}
	}
	if err = json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	a := Config{Initiator: true}
	copy(a.Player[:], unhex(v.Prologue.Player))
	copy(a.Land[:], unhex(v.Prologue.Land))
	copy(a.SID[:], unhex(v.Prologue.SID))
	copy(a.CardHash[:], unhex(v.Prologue.Card))
	for i := range a.Route {
		a.Route[i] = 0x44
	}
	static := keypair(t, unhex(f.Static))
	a.PeerStatic = static.Public
	c := a
	c.Initiator = false
	c.PeerStatic = nil
	c.StaticKey = static
	return a, c
}
func peers(t *testing.T, f nkFixture) (*Session, *Session) {
	t.Helper()
	a, b := configs(t, f)
	i, err := newSession(a, bytes.NewReader(unhex(f.Initiator)))
	if err != nil {
		t.Fatal(err)
	}
	r, err := newSession(b, bytes.NewReader(unhex(f.Responder)))
	if err != nil {
		t.Fatal(err)
	}
	return i, r
}
func complete(t *testing.T, f nkFixture) (*Session, *Session, [][]byte) {
	t.Helper()
	i, r := peers(t, f)
	a, err := i.WriteHandshake()
	if err != nil {
		t.Fatal(err)
	}
	if err = r.ReadHandshake(a); err != nil {
		t.Fatal(err)
	}
	b, err := r.WriteHandshake()
	if err != nil {
		t.Fatal(err)
	}
	if err = i.ReadHandshake(b); err != nil {
		t.Fatal(err)
	}
	return i, r, [][]byte{a, b}
}

func TestStandardNK(t *testing.T) {
	f := fixture(t)
	if len(f.Standard) != 4 {
		t.Fatal("missing standard NK known answers")
	}
	static := keypair(t, unhex(f.Static))
	suite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	i, err := noise.NewHandshakeState(noise.Config{CipherSuite: suite, Pattern: noise.HandshakeNK, Initiator: true, PeerStatic: static.Public, Random: bytes.NewReader(unhex(f.Initiator))})
	if err != nil {
		t.Fatal(err)
	}
	r, err := noise.NewHandshakeState(noise.Config{CipherSuite: suite, Pattern: noise.HandshakeNK, StaticKeypair: static, Random: bytes.NewReader(unhex(f.Responder))})
	if err != nil {
		t.Fatal(err)
	}
	a, _, _, err := i.WriteMessage(nil, nil)
	if err != nil || !bytes.Equal(a, unhex(f.Standard[0])) {
		t.Fatal("standard message 0", err)
	}
	if _, _, _, err = r.ReadMessage(nil, a); err != nil {
		t.Fatal(err)
	}
	b, r1, r2, err := r.WriteMessage(nil, nil)
	if err != nil || !bytes.Equal(b, unhex(f.Standard[1])) {
		t.Fatal("standard message 1", err)
	}
	_, i1, i2, err := i.ReadMessage(nil, b)
	if err != nil {
		t.Fatal(err)
	}
	for j, tc := range []struct {
		send, recv *noise.CipherState
		p          string
	}{{i1, r1, "yellowsubmarine"}, {r2, i2, "submarineyellow"}} {
		cipher, err := tc.send.Encrypt(nil, nil, []byte(tc.p))
		if err != nil || !bytes.Equal(cipher, unhex(f.Standard[j+2])) {
			t.Fatal("standard transport", err)
		}
		plain, err := tc.recv.Decrypt(nil, nil, cipher)
		if err != nil || string(plain) != tc.p {
			t.Fatal(err)
		}
	}
}
func project(t *testing.T, f nkFixture) *projectFixture {
	t.Helper()
	i, r, records := complete(t, f)
	a, _ := configs(t, f)
	h, err := i.HandshakeHash()
	if err != nil {
		t.Fatal(err)
	}
	rh, _ := r.HandshakeHash()
	if !bytes.Equal(h, rh) {
		t.Fatal("hash disagreement")
	}
	p := &projectFixture{Prologue: hex.EncodeToString(protocol.Prologue(a.Player, a.Land, a.SID, a.CardHash)), Hash: hex.EncodeToString(h), Negatives: []string{"altered_prologue", "wrong_static", "zero_DH", "nonempty_handshake_payload", "wrong_card", "wrong_route", "wrong_version", "repeated_sequence", "skipped_sequence", "tampered_tag", "tampered_AD", "record_budget", "byte_budget", "closed_session"}}
	for _, b := range records {
		p.Records = append(p.Records, hex.EncodeToString(b))
	}
	for _, tc := range []struct {
		s, r  *Session
		plain []byte
	}{{i, r, []byte("player-to-land")}, {r, i, []byte("land-to-player")}, {i, r, []byte{}}, {i, r, bytes.Repeat([]byte{0x42}, 32721)}} {
		cipher, err := tc.s.Encrypt(tc.plain)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := tc.r.Decrypt(cipher)
		if err != nil || !bytes.Equal(plain, tc.plain) {
			t.Fatal("project transport", err)
		}
		p.Transport = append(p.Transport, hex.EncodeToString(cipher))
		p.Plaintexts = append(p.Plaintexts, hex.EncodeToString(tc.plain))
	}
	return p
}
func TestProjectTranscript(t *testing.T) {
	f := fixture(t)
	if f.Project == nil {
		t.Fatal("project transcript NOT generated: dependency download unavailable; release blocked")
	}
	actual := project(t, f)
	a, _ := json.Marshal(actual)
	b, _ := json.Marshal(f.Project)
	if !bytes.Equal(a, b) {
		t.Fatal("project transcript/AD/expected bytes mutated")
	}
}
func TestTranscriptManifestPin(t *testing.T) {
	var m struct{ Files map[string]string }
	b, err := os.ReadFile("../../protocol/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"protocol/v1.md", "protocol/vectors/v1.json", "protocol/vectors/nk-transcript.json"} {
		b, err = os.ReadFile(filepath.Join("../..", path))
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(b)
		if m.Files[path] != hex.EncodeToString(h[:]) {
			t.Fatal("missing/mutated pin", path)
		}
	}
}

// Explicit developer-only fixture creation. It never repins the manifest or
// modifies the original frozen files. Review its output before adding the hash.
func TestGenerateProjectFixture(t *testing.T) {
	if os.Getenv("GENERATE_NK_FIXTURE") != "1" {
		t.Skip("explicit generation only")
	}
	f := fixture(t)
	f.Project = project(t, f)
	f.Notice = "Public synthetic keys only. Generated with pinned flynn/noise; standard vectors checked separately."
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile("../../protocol/vectors/nk-transcript.json", append(b, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
}
func TestHandshakeNegatives(t *testing.T) {
	f := fixture(t)
	for _, name := range []string{"altered_prologue", "wrong_static", "zero_DH", "nonempty_handshake_payload", "wrong_card", "wrong_route", "wrong_version"} {
		t.Run(name, func(t *testing.T) {
			a, b := configs(t, f)
			switch name {
			case "altered_prologue":
				b.Player[0] ^= 1
			case "wrong_static":
				other := bytes.Repeat([]byte{0x7f}, 32)
				a.PeerStatic = keypair(t, other).Public
			}
			i, err := newSession(a, bytes.NewReader(unhex(f.Initiator)))
			if err != nil {
				t.Fatal(err)
			}
			r, err := newSession(b, bytes.NewReader(unhex(f.Responder)))
			if err != nil {
				t.Fatal(err)
			}
			record, err := i.WriteHandshake()
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "zero_DH":
				clear(record[67:99])
			case "nonempty_handshake_payload":
				record = append(record, 1)
			case "wrong_card":
				record[31] ^= 1
			case "wrong_route":
				record[3] ^= 1
			case "wrong_version":
				record[2] = 2
			}
			if r.ReadHandshake(record) == nil {
				t.Fatal("accepted invalid handshake")
			}
			if r.ReadHandshake(record) == nil {
				t.Fatal("continued failed session")
			}
		})
	}
	a, _ := configs(t, f)
	a.PeerStatic = make([]byte, 32)
	if _, err := New(a); err == nil {
		t.Fatal("all-zero static accepted")
	}
}
func TestTransportNegativesAndBudgets(t *testing.T) {
	f := fixture(t)
	for _, name := range []string{"wrong_route", "wrong_version", "repeated_sequence", "skipped_sequence", "tampered_tag", "tampered_AD", "record_budget", "byte_budget", "closed_session"} {
		t.Run(name, func(t *testing.T) {
			i, r, _ := complete(t, f)
			record, err := i.Encrypt([]byte("test"))
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "wrong_route":
				record[3] ^= 1
			case "wrong_version":
				record[2] = 2
			case "repeated_sequence":
				if _, err = r.Decrypt(record); err != nil {
					t.Fatal(err)
				}
			case "skipped_sequence":
				record[26] = 1
			case "tampered_tag":
				record[len(record)-1] ^= 1
			case "tampered_AD":
				// Keep routing syntax/expected route valid, so only AEAD can
				// detect the change to the authenticated header.
				record[3] ^= 1
				r.route[0] ^= 1
			case "record_budget":
				r.receive.SetNonce(MaxRecords - 1)
			case "byte_budget":
				r.receivedBytes = MaxBytes - 16
			case "closed_session":
				r.Close()
			}
			if _, err = r.Decrypt(record); err == nil {
				t.Fatal("invalid transport accepted")
			}
			if _, err = r.Decrypt(record); err == nil {
				t.Fatal("continued failed session")
			}
		})
	}
}
