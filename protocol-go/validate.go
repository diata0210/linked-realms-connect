package protocol

import (
	"bytes"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// ValidateOrigin checks signed spelling only. DNS/IP approval and redirect policy
// must be enforced by the connecting agent, not by a codec or Hub URL fetch.
func ValidateOrigin(s string) error {
	if len(s) > 192 || !strings.HasPrefix(s, "https://") || strings.ToLower(s) != s {
		return Malformed
	}
	for _, c := range s {
		if c > 127 || c <= 32 {
			return Malformed
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(s, "?#%") || u.Host == "" {
		return Malformed
	}
	host := u.Hostname()
	port := u.Port()
	suffix := ""
	if port != "" {
		n, e := strconv.ParseUint(port, 10, 16)
		if e != nil || n == 0 || n == 443 || strconv.FormatUint(n, 10) != port {
			return Malformed
		}
		suffix = ":" + port
	}
	if ip, e := netip.ParseAddr(host); e == nil {
		canonical := ip.String()
		if ip.Is4In6() {
			// netip.String uses a dotted suffix for mapped IPv6; the signed
			// origin grammar requires the equivalent pure hexadecimal form.
			b := ip.As16()
			canonical = "::ffff:" + strconv.FormatUint(uint64(b[12])<<8|uint64(b[13]), 16) + ":" + strconv.FormatUint(uint64(b[14])<<8|uint64(b[15]), 16)
		}
		if ip.Zone() != "" || canonical != host {
			return Malformed
		}
		if ip.Is6() {
			host = "[" + host + "]"
		}
	} else {
		if len(host) > 253 || host == "" {
			return Malformed
		}
		numeric := true
		for _, c := range host {
			if c != '.' && (c < '0' || c > '9') {
				numeric = false
			}
		}
		if numeric {
			return Malformed
		}
		for _, l := range strings.Split(host, ".") {
			if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
				return Malformed
			}
			for _, c := range l {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return Malformed
				}
			}
		}
	}
	if "https://"+host+suffix != s {
		return Malformed
	}
	return nil
}
func validateEndpoints(v any) error {
	a, ok := v.([]any)
	if !ok || len(a) < 1 || len(a) > 8 {
		return Malformed
	}
	last := ""
	keys := map[string]bool{}
	for _, x := range a {
		e, ok := x.(Values)
		if !ok {
			return Malformed
		}
		s, _ := e["origin"].(string)
		k := binaryField(e, "hub_key")
		if ValidateOrigin(s) != nil || s <= last || len(k) != 32 || keys[string(k)] {
			return Malformed
		}
		last = s
		keys[string(k)] = true
	}
	return nil
}
func (e *Envelope) validate(size int) error {
	v := e.Body
	k := e.Kind
	if e.ExpiresAt < e.IssuedAt {
		return Expired
	}
	limit := uint64(60)
	if k >= 9 && k <= 11 || k >= 19 && k <= 23 {
		limit = 30
	}
	if k == 7 {
		limit = 600
	}
	if k == 26 {
		limit = 86400
	}
	if e.ExpiresAt-e.IssuedAt > limit {
		return Expired
	}
	if k == 7 || k == 26 {
		if !zero(e.Recipient[:]) || !zero(e.Context[:]) {
			return Malformed
		}
	} else if k == 9 {
		if !zero(e.Recipient[:]) || !zero(e.Context[:]) {
			return Malformed
		}
	} else if zero(e.Recipient[:]) {
		return Malformed
	}
	if k == 1 && !zero(e.Context[:]) {
		return Malformed
	}
	if n, ok := v["reason"]; ok && n.(uint64) > 16 {
		return Malformed
	}
	if n, ok := v["door_mode"]; ok && n.(uint64) > 1 {
		return Malformed
	}
	if n, ok := v["role"]; ok && n.(uint64) > 1 {
		return Malformed
	}
	if k == 20 || k == 22 {
		if number(v, "deadline") > e.ExpiresAt {
			return Expired
		}
	}
	switch k {
	case 2:
		if ValidateOrigin(v["origin"].(string)) != nil {
			return Malformed
		}
		a := v["versions"].([]any)
		if len(a) != 1 || a[0].(uint64) != 1 {
			return UnsupportedVersion
		}
		for key, max := range map[string]uint64{"max_frame": 32768, "max_card": 4096, "max_routes_per_land": 80, "max_streams": 8} {
			n := number(v, key)
			if n == 0 || n > max {
				return Malformed
			}
		}
	case 3, 29:
		if number(v, "limit") == 0 || number(v, "limit") > 64 {
			return Malformed
		}
		if k == 3 && v["land"] != nil && v["cursor"] != nil {
			return Malformed
		}
	case 4:
		var prev []byte
		for _, x := range v["entries"].([]any) {
			entry := x.(Values)
			card, err := DecodeEnvelope(binaryField(entry, "card"), DecodeOptions{})
			if err != nil {
				return err
			}
			if card.Kind != 7 || prev != nil && bytes.Compare(prev, card.Sender[:]) >= 0 || number(entry, "observed_at") != number(v, "hub_time") {
				return Malformed
			}
			prev = append([]byte(nil), card.Sender[:]...)
		}
		if next := binaryField(v, "next"); next != nil && (prev == nil || !bytes.Equal(next, prev)) {
			return Malformed
		}
	case 5, 27:
		card, err := DecodeEnvelope(binaryField(v, "card"), DecodeOptions{})
		if err != nil {
			return err
		}
		want := uint16(7)
		if k == 27 {
			want = 26
		}
		if card.Kind != want || card.Sender != e.Sender {
			return Malformed
		}
	case 7:
		if size > 4096 || e.ExpiresAt-e.IssuedAt != 600 || !bytes.Equal(e.Sender[:], binaryField(v, "land_key")) || number(v, "current_players") > number(v, "max_players") || number(v, "max_players") > 64 || number(v, "allow_guest") != 0 {
			return Malformed
		}
		if number(v, "protocol_version") != 1 {
			return UnsupportedVersion
		}
		return validateEndpoints(v["hubs"])
	case 8:
		op := number(v, "operation")
		if op < 1 || op > 32 {
			return Malformed
		}
		if op != 12 && op != 27 && op != 28 && number(v, "revision") != 0 {
			return Malformed
		}
	case 10:
		if number(v, "role") == 0 {
			if v["land"] != nil {
				return Malformed
			}
		} else if !bytes.Equal(binaryField(v, "land"), e.Sender[:]) {
			return Malformed
		}
	case 12:
		if !bytes.Equal(binaryField(v, "connection"), e.Context[:]) {
			return Malformed
		}
	case 14:
		s := v["peer_ip"].(string)
		ip, err := netip.ParseAddr(s)
		if err != nil || ip.Zone() != "" || ip.String() != s {
			return Malformed
		}
	case 19:
		if number(v, "key_class") != 0 || !bytes.Equal(binaryField(v, "land"), e.Recipient[:]) || !bytes.Equal(binaryField(v, "sid"), e.Context[:]) {
			return Malformed
		}
		if p := v["profile"]; p != nil {
			profile := p.(Values)
			if !bytes.Equal(binaryField(profile, "player_key"), e.Sender[:]) {
				return BadSignature
			}
			return validateProfile(profile)
		}
	case 21:
		if !bytes.Equal(binaryField(v, "sid"), e.Context[:]) {
			return Malformed
		}
	case 22:
		if !bytes.Equal(binaryField(v, "sid"), e.Context[:]) || !bytes.Equal(binaryField(v, "land"), e.Sender[:]) || !bytes.Equal(binaryField(v, "player"), e.Recipient[:]) {
			return Malformed
		}
	case 25:
		if e.Sender != e.Recipient {
			return Malformed
		}
	case 26:
		if size > 2048 || !bytes.Equal(binaryField(v, "poster_key"), e.Sender[:]) || number(v, "expires_at") != e.ExpiresAt || number(v, "gold_reward") > 1<<63-1 {
			return Malformed
		}
		items := v["items"].([]any)
		if len(items) < 1 {
			return Malformed
		}
		for _, x := range items {
			if number(x.(Values), "quantity") == 0 {
				return Malformed
			}
		}
	case 30:
		if size > 256*1024 {
			return Malformed
		}
		var prev []byte
		for _, x := range v["cards"].([]any) {
			card, err := DecodeEnvelope(x.([]byte), DecodeOptions{})
			if err != nil {
				return err
			}
			if card.Kind != 26 {
				return Malformed
			}
			tuple := append(append([]byte(nil), binaryField(card.Body, "quest_id")...), card.Sender[:]...)
			if prev != nil && bytes.Compare(prev, tuple) >= 0 {
				return Malformed
			}
			prev = tuple
		}
		if v["next"] != nil {
			n := v["next"].(Values)
			tuple := append(append([]byte(nil), binaryField(n, "quest_id")...), binaryField(n, "poster_key")...)
			if !bytes.Equal(tuple, prev) {
				return Malformed
			}
		}
	case 31:
		if number(v, "quantity") == 0 || !bytes.Equal(binaryField(v, "taker"), e.Sender[:]) {
			return Malformed
		}
	case 32:
		if number(v, "status") > 2 {
			return Malformed
		}
	}
	return nil
}
