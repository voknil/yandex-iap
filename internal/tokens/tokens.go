// Package tokens stores long-lived bearer tokens used by automated clients
// (smoke tests, CI jobs, automation scripts) that can't complete an interactive OAuth
// flow.
//
// A token is issued once at creation time (format: "yiap_<40 hex chars>") and
// shown to the admin exactly once. Only a SHA-256 digest plus a short
// fingerprint ("last4") lands on disk, so a stolen file does not leak the
// active credentials — but it also means a forgotten token cannot be
// recovered, only rotated.
//
// The file format is a simple JSON array. Writes are performed atomically
// through a tempfile + rename, readers are cached for 5 seconds like the
// whitelist.
package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Record is one line in the persisted JSON file.
type Record struct {
	// ID is a short opaque identifier ("tok_" + 8 hex chars); used as the
	// delete-handle in the admin UI. Separate from the token itself so a URL
	// or HTML form can reference a token without ever serialising it.
	ID string `json:"id"`

	// Name is a free-text label the admin picked at creation time —
	// e.g. "cypress ci", "uptime probe", "metrics scraper".
	Name string `json:"name"`

	// Hash is the lowercase-hex SHA-256 of the token bytes.
	Hash string `json:"hash"`

	// Last4 is the last 4 hex characters of the token — purely for UI
	// ("…xyz1"), never used for authentication.
	Last4 string `json:"last4"`

	// CreatedAt is RFC3339 UTC.
	CreatedAt string `json:"created_at"`

	// CreatedBy is the admin email that issued the token. Blank when the
	// file was populated by an external tool.
	CreatedBy string `json:"created_by,omitempty"`
}

// Store is the small interface consumed by the HTTP layer.
type Store interface {
	// List returns all records, newest first.
	List() ([]Record, error)

	// Create mints a new token. Returns the plaintext token ONCE so the
	// caller can show it to the admin — no server-side recovery path exists
	// afterwards.
	Create(name, createdBy string) (Record, string, error)

	// Delete removes the record with the given ID. Idempotent.
	Delete(id string) error

	// Validate checks whether the given plaintext token matches any record.
	// Returns the matching Record if so, or (nil, false).
	Validate(plaintext string) (*Record, bool)
}

// ErrInvalidName is returned by Create when the label is empty or too long.
var ErrInvalidName = errors.New("token name must be 1–80 characters")

// File is the file-backed Store.
type File struct {
	path         string
	refreshAfter time.Duration

	mu       sync.RWMutex
	loaded   time.Time
	records  []Record
	byHash   map[string]int // hash -> index in records
}

// NewFile returns a file-backed Store. refreshAfter=0 means "reload on every
// read", useful for tests.
func NewFile(path string, refreshAfter time.Duration) *File {
	return &File{path: path, refreshAfter: refreshAfter}
}

func (f *File) refreshIfStale() error {
	f.mu.RLock()
	if f.records != nil && f.refreshAfter > 0 && time.Since(f.loaded) < f.refreshAfter {
		f.mu.RUnlock()
		return nil
	}
	f.mu.RUnlock()

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.records != nil && f.refreshAfter > 0 && time.Since(f.loaded) < f.refreshAfter {
		return nil
	}
	return f.loadLocked()
}

// loadLocked reads records from disk, swapping the in-memory caches.
// Must be called with f.mu held for writing.
func (f *File) loadLocked() error {
	data, err := os.ReadFile(f.path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var recs []Record
	if len(data) > 0 {
		if err := json.Unmarshal(data, &recs); err != nil {
			return fmt.Errorf("parse %s: %w", f.path, err)
		}
	}
	idx := make(map[string]int, len(recs))
	for i, r := range recs {
		if r.Hash != "" {
			idx[r.Hash] = i
		}
	}
	f.records = recs
	f.byHash = idx
	f.loaded = time.Now()
	return nil
}

// List returns a copy of the records, newest first.
func (f *File) List() ([]Record, error) {
	if err := f.refreshIfStale(); err != nil {
		return nil, err
	}
	f.mu.RLock()
	defer f.mu.RUnlock()

	out := make([]Record, len(f.records))
	copy(out, f.records)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].CreatedAt > out[j].CreatedAt
	})
	return out, nil
}

// Create mints a new token.
func (f *File) Create(name, createdBy string) (Record, string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 80 {
		return Record{}, "", ErrInvalidName
	}

	plaintext, err := generateToken()
	if err != nil {
		return Record{}, "", err
	}
	sum := sha256.Sum256([]byte(plaintext))
	hashHex := hex.EncodeToString(sum[:])

	rec := Record{
		ID:        "tok_" + randomID(),
		Name:      name,
		Hash:      hashHex,
		Last4:     plaintext[len(plaintext)-4:],
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		CreatedBy: strings.TrimSpace(createdBy),
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.records == nil {
		if err := f.loadLocked(); err != nil {
			return Record{}, "", err
		}
	}
	f.records = append(f.records, rec)
	f.byHash[hashHex] = len(f.records) - 1
	if err := f.persistLocked(); err != nil {
		// Roll back in-memory state so we don't serve a record that isn't on disk.
		f.records = f.records[:len(f.records)-1]
		delete(f.byHash, hashHex)
		return Record{}, "", err
	}
	return rec, plaintext, nil
}

// Delete removes the record with the given ID. Idempotent.
func (f *File) Delete(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.records == nil {
		if err := f.loadLocked(); err != nil {
			return err
		}
	}
	kept := make([]Record, 0, len(f.records))
	var removed *Record
	for _, r := range f.records {
		if r.ID == id {
			removed = &r
			continue
		}
		kept = append(kept, r)
	}
	if removed == nil {
		return nil // idempotent
	}
	f.records = kept
	delete(f.byHash, removed.Hash)
	// Rebuild the byHash index — indices shifted after the slice compaction.
	for i, r := range f.records {
		f.byHash[r.Hash] = i
	}
	return f.persistLocked()
}

// Validate checks whether plaintext matches any record. It does a short-circuit
// map lookup by hash; constant-time comparison is performed on the hex digest
// itself so a timing attacker learns nothing about which token hashed to what.
func (f *File) Validate(plaintext string) (*Record, bool) {
	if err := f.refreshIfStale(); err != nil {
		return nil, false
	}
	sum := sha256.Sum256([]byte(plaintext))
	want := hex.EncodeToString(sum[:])

	f.mu.RLock()
	defer f.mu.RUnlock()
	idx, ok := f.byHash[want]
	if !ok {
		return nil, false
	}
	// Constant-time check against the canonical hash.
	rec := f.records[idx]
	if subtle.ConstantTimeCompare([]byte(rec.Hash), []byte(want)) != 1 {
		return nil, false
	}
	return &rec, true
}

// persistLocked writes records to disk atomically. Must be called with the
// write lock held.
func (f *File) persistLocked() error {
	dir := filepath.Dir(f.path)
	tmp, err := os.CreateTemp(dir, ".iap-tokens-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f.records); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), f.path)
}

// generateToken returns a 40-hex-char random token with the "yiap_" prefix,
// giving 160 bits of entropy.
func generateToken() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "yiap_" + hex.EncodeToString(b), nil
}

// randomID produces an 8-hex-char ID for record handles in URLs/forms.
func randomID() string {
	b := make([]byte, 4)
	// crypto/rand.Read never returns an error in practice; even if it did,
	// falling through to a zero ID is worse than panicking.
	if _, err := rand.Read(b); err != nil {
		panic("tokens: cannot read random bytes: " + err.Error())
	}
	return hex.EncodeToString(b)
}
