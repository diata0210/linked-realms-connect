package protocol

import (
	"sync"
	"time"
)

// CheckTime uses subtraction to avoid overflow at u64 boundaries. Returned
// seconds are a duration from acceptance, to be measured on a monotonic clock.
func CheckTime(issued, expires, now, lifetime uint64) (uint64, error) {
	if issued > expires || expires-issued > lifetime || issued > now && issued-now > 120 || now > expires && now-expires > 120 {
		return 0, Expired
	}
	retention := uint64(180)
	if expires >= now {
		d := expires - now
		if d > ^uint64(0)-120 {
			return 0, Expired
		}
		d += 120
		if d > retention {
			retention = d
		}
	} else {
		d := now - expires
		if d < 120 && 120-d > retention {
			retention = 120 - d
		}
	}
	return retention, nil
}
func (e *Envelope) CheckTime(now uint64) (uint64, error) {
	if e.Kind == 7 || e.Kind == 26 {
		if now >= e.ExpiresAt || e.IssuedAt > now && e.IssuedAt-now > 120 {
			return 0, Expired
		}
		return 0, nil
	}
	max := uint64(60)
	if e.Kind >= 9 && e.Kind <= 11 || e.Kind >= 19 && e.Kind <= 23 {
		max = 30
	}
	return CheckTime(e.IssuedAt, e.ExpiresAt, now, max)
}

type nonceKey struct {
	Sender  [32]byte
	Context [16]byte
	Nonce   [32]byte
}
type ReplayCache struct {
	mu       sync.Mutex
	capacity int
	entries  map[nonceKey]time.Time
	clock    func() time.Time
}

func NewReplayCache(capacity int) *ReplayCache {
	return &ReplayCache{capacity: capacity, entries: map[nonceKey]time.Time{}, clock: time.Now}
}

// Accept records authenticated requests before application policy evaluation,
// including requests which will be denied. Never use this for stored objects.
func (c *ReplayCache) Accept(e *Envelope, wall uint64) error {
	if e.Kind == 7 || e.Kind == 26 {
		return Malformed
	}
	seconds, err := e.CheckTime(wall)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock()
	for k, until := range c.entries {
		if !now.Before(until) {
			delete(c.entries, k)
		}
	}
	k := nonceKey{e.Sender, e.Context, e.Nonce}
	if _, ok := c.entries[k]; ok {
		return Replay
	}
	if len(c.entries) >= c.capacity {
		return Busy
	}
	c.entries[k] = now.Add(time.Duration(seconds) * time.Second)
	return nil
}
