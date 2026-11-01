package protocol

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestControlFrameAuthorContext(t *testing.T) {
	for _, hub := range []bool{false, true} {
		t.Run(map[bool]string{false: "peer", true: "hub"}[hub], func(t *testing.T) {
			body := Values{"route": make([]byte, 16), "reason": uint64(0)}
			if hub {
				body["request_hash"] = make([]byte, 32)
				body["hub_time"] = uint64(1000)
				body["hub_boot"] = make([]byte, 16)
			}
			e := &Envelope{Kind: 16, HubAuthored: hub, IssuedAt: 1000, ExpiresAt: 1060, Body: body}
			copy(e.Recipient[:], ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)).Public().(ed25519.PublicKey))
			e.Context[0] = 1
			if err := e.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))); err != nil {
				t.Fatal(err)
			}
			payload, err := e.Encode()
			if err != nil {
				t.Fatal(err)
			}
			raw, err := (&Frame{Type: 0, Payload: payload, HubAuthored: hub}).Encode()
			if err != nil {
				t.Fatal(err)
			}
			frame, err := DecodeFrame(raw, [16]byte{}, 0, DecodeOptions{HubAuthored: hub})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(frame.Payload, payload) || frame.HubAuthored != hub {
				t.Fatal("lost payload/author context")
			}
			if _, err := DecodeFrame(raw, [16]byte{}, 0, DecodeOptions{HubAuthored: !hub}); err == nil {
				t.Fatal("accepted wrong authenticated author context")
			}
			if !hub {
				if _, err := DecodeFrame(raw, [16]byte{}, 0); err != nil {
					t.Fatal("broke existing peer decoder", err)
				}
			}
		})
	}
	if _, err := DecodeFrame([]byte{0}, [16]byte{}, 0, DecodeOptions{}, DecodeOptions{}); err != Malformed {
		t.Fatal("ambiguous options", err)
	}
}
