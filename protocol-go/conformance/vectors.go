// Package conformance runs public vectors against this module's production
// codecs. Consumers import it from the SAME pinned module as their codecs.
package conformance

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	p "github.com/diata0210/linked-realms-connect/protocol-go"
	"strconv"
)

type Result struct {
	Name string
	Err  error
}
type vector struct {
	Name, Expect, Scope string
	Error               struct{ Code int }
	Envelope            string   `json:"envelope_hex"`
	Body                string   `json:"body_hex"`
	Header              string   `json:"header_hex"`
	Signed              string   `json:"signed_bytes_hex"`
	Signature           string   `json:"signature_hex"`
	Hash                string   `json:"sha256_hex"`
	Bytes               string   `json:"bytes_hex"`
	Frame               string   `json:"frame_hex"`
	AD                  string   `json:"associated_data_hex"`
	Next                string   `json:"next_sequence"`
	Plaintext           string   `json:"plaintext_hex"`
	Input               string   `json:"input_hex"`
	Type                string   `json:"input_type"`
	Max                 int      `json:"max_bytes"`
	Rows                [][2]any `json:"input_rows"`
	Start               int
	Issued              string `json:"issued_at"`
	Expires             string `json:"expires_at"`
	Now                 string
	Retention           uint64 `json:"minimum_retention_seconds"`
	URL                 string
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("invalid fixture hex: " + err.Error())
	}
	return b
}
func decimal(s string) uint64 {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		panic("invalid fixture decimal")
	}
	return n
}
func compare(got []byte, want string) error {
	if want != "" && !bytes.Equal(got, unhex(want)) {
		return fmt.Errorf("encoded bytes mismatch")
	}
	return nil
}

// CheckVectors covers wire/object/frame/operation/time/table fixtures. Agent-only
// key-file and derivation fixtures are exercised in the agent module, never Hub.
func CheckVectors(data []byte) (results []Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("invalid vector fixture: %v", r)
		}
	}()
	var groups map[string]json.RawMessage
	if err = json.Unmarshal(data, &groups); err != nil {
		return nil, err
	}
	for _, group := range []string{"envelopes", "wallet", "negative", "objects", "operations", "frames", "time", "quest_pagination"} {
		var cases []vector
		if err = json.Unmarshal(groups[group], &cases); err != nil || len(cases) == 0 {
			return nil, fmt.Errorf("missing vector group %s", group)
		}
		for _, v := range cases {
			actual := check(v, group)
			if v.Expect == "reject" {
				if actual != p.Code(v.Error.Code) {
					actual = fmt.Errorf("got %v, expected protocol error %d", actual, v.Error.Code)
				} else {
					actual = nil
				}
			} else if v.Expect != "accept" {
				actual = fmt.Errorf("unknown expected outcome")
			}
			results = append(results, Result{group + "/" + v.Name, actual})
		}
	}
	var pro struct {
		Player string `json:"player_hex"`
		Land   string `json:"land_hex"`
		SID    string `json:"sid_hex"`
		Card   string `json:"card_sha256_hex"`
		Bytes  string `json:"bytes_hex"`
	}
	if err = json.Unmarshal(groups["prologue"], &pro); err != nil || pro.Bytes == "" {
		return nil, fmt.Errorf("missing prologue")
	}
	var player, land, card [32]byte
	var sid [16]byte
	copy(player[:], unhex(pro.Player))
	copy(land[:], unhex(pro.Land))
	copy(card[:], unhex(pro.Card))
	copy(sid[:], unhex(pro.SID))
	results = append(results, Result{"prologue", compare(p.Prologue(player, land, sid, card), pro.Bytes)})
	return results, nil
}
func check(v vector, group string) error {
	if v.Envelope != "" {
		raw := unhex(v.Envelope)
		e, err := p.DecodeEnvelope(raw, p.DecodeOptions{})
		if err != nil {
			return err
		}
		b, err := e.Encode()
		if err != nil {
			return err
		}
		if !bytes.Equal(b, raw) {
			return fmt.Errorf("envelope round trip")
		}
		for _, pair := range []struct {
			got  []byte
			want string
		}{{b[140 : len(b)-64], v.Body}, {b[:140], v.Header}, {b[len(b)-64:], v.Signature}, {append([]byte(p.ControlDomain), b[:len(b)-64]...), v.Signed}} {
			if err = compare(pair.got, pair.want); err != nil {
				return err
			}
		}
		h := p.Hash(b)
		return compare(h[:], v.Hash)
	}
	switch group {
	case "negative":
		if v.Scope == "primitive" {
			_, err := p.DecodePrimitive(unhex(v.Input), v.Type, v.Max)
			return err
		}
		if v.Scope == "table_validation" {
			for i := range v.Rows {
				v.Rows[i][0] = int(v.Rows[i][0].(float64))
			}
			return p.ValidateTable(v.Rows, v.Start)
		}
	case "objects":
		raw := unhex(v.Bytes)
		var b []byte
		var err error
		switch v.Name {
		case "signed_profile_preset":
			o, e := p.DecodeProfile(raw)
			if e != nil {
				return e
			}
			b, err = p.EncodeProfile(o)
			if err == nil {
				err = compare(append([]byte(p.ProfileDomain), raw[:len(raw)-64]...), v.Signed)
			}
		case "invite_link":
			o, e := p.DecodeInvite(raw)
			if e != nil {
				return e
			}
			b, err = p.EncodeInvite(o)
			if err == nil {
				var url string
				url, err = p.EncodeInviteURL(o)
				if err == nil && url != v.URL {
					return fmt.Errorf("invite URL mismatch")
				}
				if err == nil {
					_, err = p.DecodeInviteURL(url, 1700000000)
				}
				if err == nil {
					err = compare(append([]byte(p.InviteDomain), raw[:len(raw)-64]...), v.Signed)
				}
			}
		default:
			return fmt.Errorf("unhandled object %s", v.Name)
		}
		if err != nil {
			return err
		}
		if !bytes.Equal(raw, b) {
			return fmt.Errorf("object round trip")
		}
		return nil
	case "operations":
		raw := unhex(v.Plaintext)
		o, err := p.DecodeOperation(raw)
		if err != nil {
			return err
		}
		b, err := o.Encode()
		if err != nil {
			return err
		}
		if !bytes.Equal(raw, b) {
			return fmt.Errorf("operation round trip")
		}
		return compare(b[6:], v.Body)
	case "frames":
		raw := unhex(v.Frame)
		var route [16]byte
		for i := range route {
			route[i] = 0x44
		}
		f, err := p.DecodeFrame(raw, route, decimal(v.Next))
		if err != nil {
			return err
		}
		b, err := f.Encode()
		if err != nil {
			return err
		}
		if !bytes.Equal(raw, b) {
			return fmt.Errorf("frame round trip")
		}
		if v.AD != "" {
			return compare(b[:31], v.AD)
		}
		return nil
	case "time":
		retention, err := p.CheckTime(decimal(v.Issued), decimal(v.Expires), decimal(v.Now), 60)
		if err != nil {
			return err
		}
		if retention != v.Retention {
			return fmt.Errorf("retention %d != %d", retention, v.Retention)
		}
		return nil
	}
	return fmt.Errorf("unhandled vector %s/%s", group, v.Name)
}
