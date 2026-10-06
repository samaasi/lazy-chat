package errors

import (
	stderrors "errors"
	"fmt"
	"sync"
	"testing"
)

func TestWithContextDoesNotMutateSentinel(t *testing.T) {
	before := len(ErrPeerNotFound.Context)
	derived := ErrPeerNotFound.WithContext("peer_id", "abc")
	if len(ErrPeerNotFound.Context) != before {
		t.Fatalf("sentinel was mutated: %v", ErrPeerNotFound.Context)
	}
	if derived.Context["peer_id"] != "abc" {
		t.Fatalf("derived error lost its context: %v", derived.Context)
	}
}

// Run with -race: this used to be a "concurrent map writes" crash.
func TestWithContextConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = ErrMessageValidation.WithContext("n", i).Error()
		}()
	}
	wg.Wait()
}

func TestIsMatchesDerivedCopies(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", ErrPeerNotFound.WithContext("peer_id", "x"))
	if !stderrors.Is(err, ErrPeerNotFound) {
		t.Fatal("errors.Is should match a derived copy by code")
	}
	if stderrors.Is(err, ErrPeerNotConnected) {
		t.Fatal("different codes must not match")
	}
	if !IsPeerError(err) || IsNetworkError(err) {
		t.Fatal("type helpers should see through wrapping")
	}
}

func TestErrorStringHasNoDuplicates(t *testing.T) {
	got := Wrap(fmt.Errorf("boom"), ErrorTypeNetwork, "NET001", "failed").Error()
	want := "network [NET001]: failed (caused by: boom)"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
