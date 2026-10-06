package offline

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/samaasi/lazy-chat/internal/identity"
	"github.com/samaasi/lazy-chat/internal/storage"
)

const (
	// SPKRotate: a new signed prekey is made when the newest is this old.
	SPKRotate = 7 * 24 * time.Hour
	// SPKRetain: how long an old signed prekey is kept so that messages
	// encrypted to an older bundle can still be opened.
	SPKRetain = 28 * time.Hour * 24
	// senderMaxAge: a sender refuses to encrypt to a cached signed prekey older
	// than this. It is safely inside SPKRetain, so a message sealed to a cached
	// bundle can still be opened by its owner.
	senderMaxAge = 21 * 24 * time.Hour

	opkTTL      = 60 * 24 * time.Hour
	opkBatch    = 10
	opkLow      = 4
	maxOPKTotal = 2000 // bounds the prekeys a swarm of throwaway identities can make us create
	maxBundles  = 5000
	maxUsed     = 256
)

// Service manages our prekeys and the bundles of other peers, backed by storage.
type Service struct {
	id    *identity.Identity
	store storage.PrekeyStorage
	now   func() time.Time
	mu    sync.Mutex // serialises read-modify-write of prekeys and cached bundles
}

// NewService creates the prekey service for our identity.
func NewService(id *identity.Identity, store storage.PrekeyStorage) *Service {
	return &Service{id: id, store: store, now: time.Now}
}

// ---- Our own prekeys ------------------------------------------------------------

func (s *Service) currentSPK(ctx context.Context) (*storage.SPKRecord, error) {
	recent, err := s.store.ListSPKs(ctx, s.now().Add(-SPKRotate))
	if err != nil {
		return nil, err
	}
	if len(recent) > 0 && len(recent[0].Sig) > 0 {
		return &recent[0], nil
	}

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	rec := storage.SPKRecord{Pub: priv.PublicKey().Bytes(), Priv: priv.Bytes(), Created: s.now()}
	// The signature covers the ID, which the database assigns.
	if rec.ID, err = s.store.SaveSPK(ctx, rec); err != nil {
		return nil, err
	}
	rec.Sig = SignPrekey(s.id, rec.ID, rec.Pub, rec.Created.Unix()).Sig
	if err := s.store.UpdateSPKSignature(ctx, rec.ID, rec.Sig); err != nil {
		return nil, err
	}
	return &rec, nil
}

// baseBundle is our bundle without one-time prekeys. The caller holds s.mu.
func (s *Service) baseBundle(ctx context.Context) (*Bundle, error) {
	spk, err := s.currentSPK(ctx)
	if err != nil {
		return nil, fmt.Errorf("signed prekey: %w", err)
	}
	return NewBundle(s.id, SignedPrekey{ID: spk.ID, Pub: spk.Pub, Created: spk.Created.Unix(), Sig: spk.Sig}), nil
}

// OurBundleFor returns our bundle for the given peer: a current signed prekey
// plus one-time prekeys reserved for that peer alone. Reserving them per peer
// means two senders can never use the same one-time prekey.
func (s *Service) OurBundleFor(ctx context.Context, peerID string) (*Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := s.baseBundle(ctx)
	if err != nil {
		return nil, err
	}

	unused, err := s.store.UnusedOPKs(ctx, peerID)
	if err != nil {
		return nil, err
	}
	if len(unused) < opkLow {
		total, err := s.store.CountOPKs(ctx)
		if err != nil {
			return nil, err
		}
		want := min(opkBatch-len(unused), maxOPKTotal-total)
		var fresh []storage.OPKRecord
		for range max(want, 0) {
			k, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				return nil, err
			}
			fresh = append(fresh, storage.OPKRecord{Pub: k.PublicKey().Bytes(), Priv: k.Bytes(), ReservedFor: peerID, Created: s.now()})
		}
		if len(fresh) > 0 {
			if _, err := s.store.CreateOPKs(ctx, fresh); err != nil {
				return nil, err
			}
			if unused, err = s.store.UnusedOPKs(ctx, peerID); err != nil {
				return nil, err
			}
		}
	}
	for _, o := range unused {
		b.OPKs = append(b.OPKs, OneTimePrekey{ID: o.ID, Pub: o.Pub})
	}
	return b, nil
}

// ownKeys exposes our private prekeys to Open.
type ownKeys struct {
	ctx   context.Context
	store storage.PrekeyStorage
}

func (k ownKeys) SPK(id uint32) (*ecdh.PrivateKey, bool) {
	r, err := k.store.GetSPK(k.ctx, id)
	if err != nil {
		return nil, false
	}
	key, err := ecdh.X25519().NewPrivateKey(r.Priv)
	return key, err == nil
}

func (k ownKeys) OPK(id uint32, reservedFor string) (*ecdh.PrivateKey, bool) {
	r, err := k.store.GetOPK(k.ctx, id, reservedFor)
	if err != nil {
		return nil, false
	}
	key, err := ecdh.X25519().NewPrivateKey(r.Priv)
	return key, err == nil
}

// Open decrypts a sealed message addressed to us and destroys the one-time
// prekey it used, so the message cannot be opened again.
func (s *Service) Open(ctx context.Context, blob []byte) (plaintext []byte, senderID string, err error) {
	return s.OpenThen(ctx, blob, nil)
}

// OpenThen is Open with a commit step. accept is called with the plaintext and
// the authenticated sender; only if it returns nil is the one-time prekey
// destroyed. Store the message in accept: a crash before it finishes then
// leaves the message openable again instead of lost. (If the crash comes
// after storing but before the prekey is destroyed, the replayed message is
// harmless because messages are deduplicated by ID.)
func (s *Service) OpenThen(ctx context.Context, blob []byte, accept func(plaintext []byte, senderID string) error) ([]byte, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	plaintext, senderID, opkID, err := Open(s.id, ownKeys{ctx, s.store}, blob)
	if err != nil {
		return nil, "", err
	}
	if accept != nil {
		if err := accept(plaintext, senderID); err != nil {
			return nil, "", err
		}
	}
	if opkID != 0 {
		if err := s.store.DeleteOPK(ctx, opkID); err != nil {
			return nil, "", fmt.Errorf("could not destroy used prekey: %w", err)
		}
	}
	return plaintext, senderID, nil
}

// Maintain deletes expired prekeys and prunes the bundle cache. The newest
// signed prekey is always kept.
func (s *Service) Maintain(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if _, err := s.store.DeleteSPKsBefore(ctx, now.Add(-SPKRetain)); err != nil {
		return err
	}
	if _, err := s.store.DeleteOPKsBefore(ctx, now.Add(-opkTTL)); err != nil {
		return err
	}
	_, err := s.store.PruneBundles(ctx, maxBundles)
	return err
}

// ---- Other peers' bundles ----------------------------------------------------------

// stored is what we keep per peer: their bundle and the one-time prekeys of it
// that we have already used.
type stored struct {
	Bundle Bundle   `json:"bundle"`
	Used   []uint32 `json:"used,omitempty"`
}

func (s *Service) load(ctx context.Context, peerID string) (*stored, error) {
	data, _, err := s.store.GetBundle(ctx, peerID)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st stored
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, nil // unreadable cache entry: behave as if we had none
	}
	return &st, nil
}

func (s *Service) save(ctx context.Context, peerID string, st *stored) error {
	if len(st.Used) > maxUsed {
		st.Used = st.Used[len(st.Used)-maxUsed:]
	}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.store.SaveBundle(ctx, peerID, data, s.now())
}

// RememberBundle verifies a bundle (it must belong to peerID) and merges it
// with what we already know: the newest signed prekey wins, one-time prekeys
// accumulate, and one we already used is never offered again, even if the
// peer's next announcement still lists it.
func (s *Service) RememberBundle(ctx context.Context, peerID string, b *Bundle) error {
	id, err := b.Verify()
	if err != nil {
		return err
	}
	if id != peerID {
		return fmt.Errorf("%w: bundle belongs to %s, not %s", ErrBadBundle, id, peerID)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := s.load(ctx, peerID)
	if err != nil {
		return err
	}
	st := &stored{Bundle: *b}
	if cur != nil {
		st.Used = cur.Used
		if cur.Bundle.SPK.Created > b.SPK.Created ||
			(cur.Bundle.SPK.Created == b.SPK.Created && cur.Bundle.SPK.ID > b.SPK.ID) {
			st.Bundle = cur.Bundle // keep the newer signed prekey we already had
		}
		have := map[uint32]bool{}
		for _, o := range b.OPKs {
			have[o.ID] = true
		}
		st.Bundle.OPKs = slices.Clone(b.OPKs)
		for _, o := range cur.Bundle.OPKs {
			if !have[o.ID] {
				st.Bundle.OPKs = append(st.Bundle.OPKs, o)
			}
		}
	}
	// Never resurrect a used one-time prekey.
	st.Bundle.OPKs = slices.DeleteFunc(slices.Clone(st.Bundle.OPKs), func(o OneTimePrekey) bool {
		return slices.Contains(st.Used, o.ID)
	})
	if len(st.Bundle.OPKs) > MaxOPKs {
		st.Bundle.OPKs = st.Bundle.OPKs[:MaxOPKs]
	}
	return s.save(ctx, peerID, st)
}

// HasBundle reports whether we could encrypt to peerID right now.
func (s *Service) HasBundle(ctx context.Context, peerID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.load(ctx, peerID)
	return err == nil && st != nil && s.fresh(&st.Bundle)
}

func (s *Service) fresh(b *Bundle) bool {
	return s.now().Sub(time.Unix(b.SPK.Created, 0)) <= senderMaxAge
}

// BundleForGossip returns a bundle we hold for peerID, without one-time
// prekeys (those are reserved for whoever the owner gave them to). The bundle
// is self-certifying, so the recipient of the gossip can verify it.
func (s *Service) BundleForGossip(ctx context.Context, peerID string) (*Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if peerID == s.id.ID() {
		return s.baseBundle(ctx)
	}
	st, err := s.load(ctx, peerID)
	if err != nil {
		return nil, err
	}
	if st == nil || !s.fresh(&st.Bundle) {
		return nil, ErrNoBundle
	}
	b := st.Bundle
	b.OPKs = nil
	return &b, nil
}

// Seal encrypts plaintext to recipientID using the bundle we hold for them,
// consuming one of their one-time prekeys if one is available.
func (s *Service) Seal(ctx context.Context, recipientID string, plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, err := s.load(ctx, recipientID)
	if err != nil {
		return nil, err
	}
	if st == nil || !s.fresh(&st.Bundle) {
		return nil, ErrNoBundle
	}
	if id, err := st.Bundle.Verify(); err != nil || id != recipientID {
		return nil, ErrNoBundle
	}

	var opk *OneTimePrekey
	if len(st.Bundle.OPKs) > 0 {
		o := st.Bundle.OPKs[0]
		opk = &o
		st.Bundle.OPKs = st.Bundle.OPKs[1:]
		st.Used = append(st.Used, o.ID)
		// Persist before sealing: a prekey must never be used twice.
		if err := s.save(ctx, recipientID, st); err != nil {
			return nil, err
		}
	}
	return Seal(s.id, recipientID, &st.Bundle, opk, plaintext)
}
