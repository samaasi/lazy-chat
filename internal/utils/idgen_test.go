package utils

import (
	"sync"
	"testing"
)

func TestIDsAreUniqueUnderConcurrency(t *testing.T) {
	const n = 20000
	var (
		mu   sync.Mutex
		seen = make(map[string]struct{}, n)
		wg   sync.WaitGroup
	)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range n / 8 {
				id := NewID()
				if len(id) != 32 {
					t.Errorf("unexpected id length %d", len(id))
				}
				mu.Lock()
				if _, dup := seen[id]; dup {
					t.Errorf("duplicate id %s", id)
				}
				seen[id] = struct{}{}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
}

func TestPrefixedID(t *testing.T) {
	if id := NewPrefixedID("grp"); len(id) != 4+32 || id[:4] != "grp_" {
		t.Fatalf("bad prefixed id %q", id)
	}
}
