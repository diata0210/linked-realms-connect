package noisesession

import (
	protocol "github.com/diata0210/linked-realms-connect/protocol-go"
	"testing"
)

func reviewClosed(t *testing.T, s *Session) {
	t.Helper()
	if !s.closed || s.hs != nil || s.send != nil || s.receive != nil || s.hash != nil {
		t.Fatal("failed session retains accessible key state")
	}
	if _, err := s.HandshakeHash(); err == nil {
		t.Fatal("hash after close")
	}
	if out, err := s.Encrypt(nil); err == nil || out != nil {
		t.Fatal("encrypt after failure")
	}
}
func TestActualNoiseBudgetBoundaries(t *testing.T) {
	f := fixture(t)
	t.Run("send_records", func(t *testing.T) {
		i, r, _ := complete(t, f)
		i.send.SetNonce(MaxRecords - 2)
		r.receive.SetNonce(MaxRecords - 2)
		rec, err := i.Encrypt(nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = r.Decrypt(rec); err != nil {
			t.Fatal(err)
		}
		if _, err = i.Encrypt(nil); err != protocol.Busy {
			t.Fatal("send limit", err)
		}
		reviewClosed(t, i)
	})
	t.Run("receive_records", func(t *testing.T) {
		i, r, _ := complete(t, f)
		i.send.SetNonce(MaxRecords - 1)
		r.receive.SetNonce(MaxRecords - 1)
		h, err := protocol.FrameHeader(2, i.route, MaxRecords-1, 16)
		if err != nil {
			t.Fatal(err)
		}
		cipher, err := i.send.Encrypt(nil, h, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = r.Decrypt(append(h, cipher...)); err != protocol.Busy {
			t.Fatal("receive limit", err)
		}
		reviewClosed(t, r)
	})
	t.Run("send_bytes", func(t *testing.T) {
		i, _, _ := complete(t, f)
		i.sentBytes = MaxBytes - 17
		if _, err := i.Encrypt(nil); err != nil {
			t.Fatal(err)
		}
		if _, err := i.Encrypt(nil); err != protocol.Busy {
			t.Fatal("send bytes limit", err)
		}
		reviewClosed(t, i)
	})
	t.Run("receive_bytes", func(t *testing.T) {
		i, r, _ := complete(t, f)
		r.receivedBytes = MaxBytes - 17
		rec, err := i.Encrypt(nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = r.Decrypt(rec); err != nil {
			t.Fatal(err)
		}
		rec, err = i.Encrypt(nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = r.Decrypt(rec); err != protocol.Busy {
			t.Fatal("receive bytes limit", err)
		}
		reviewClosed(t, r)
	})
}
