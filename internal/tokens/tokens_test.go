package tokens

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCreateValidateDelete(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	f := NewFile(path, 0)

	rec, plaintext, err := f.Create("cypress smoke", "admin@example.com", 0)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !strings.HasPrefix(plaintext, "yiap_") || len(plaintext) != len("yiap_")+40 {
		t.Errorf("unexpected token shape: %q", plaintext)
	}
	if rec.Last4 != plaintext[len(plaintext)-4:] {
		t.Errorf("Last4 mismatch: rec=%q plain=%q", rec.Last4, plaintext)
	}
	if rec.Hash == "" || strings.Contains(rec.Hash, plaintext) {
		t.Errorf("hash must be non-empty and not contain plaintext; got %q", rec.Hash)
	}

	// Validate the token we just made.
	got, ok := f.Validate(plaintext)
	if !ok || got == nil {
		t.Fatalf("Validate: expected match, got ok=%v", ok)
	}
	if got.ID != rec.ID {
		t.Errorf("matched record ID: got %q, want %q", got.ID, rec.ID)
	}

	// A different token must not match.
	if _, ok := f.Validate("yiap_notarealtoken"); ok {
		t.Errorf("Validate: unexpected match for bogus token")
	}

	// Reload from disk — persistence round-trip.
	f2 := NewFile(path, 0)
	if _, ok := f2.Validate(plaintext); !ok {
		t.Errorf("token did not survive reload from disk")
	}

	// Delete and re-validate.
	if err := f.Delete(rec.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := f.Validate(plaintext); ok {
		t.Errorf("Validate: deleted token must not match")
	}
	if err := f.Delete(rec.ID); err != nil {
		t.Errorf("Delete is expected to be idempotent: %v", err)
	}
}

func TestListNewestFirst(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	f := NewFile(path, 0)

	r1, _, _ := f.Create("first", "admin", 0)
	time.Sleep(time.Second) // CreatedAt has second precision
	r2, _, _ := f.Create("second", "admin", 0)

	list, err := f.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 records, got %d", len(list))
	}
	if list[0].ID != r2.ID || list[1].ID != r1.ID {
		t.Errorf("expected newest first: got %v, %v", list[0].ID, list[1].ID)
	}
}

func TestRejectsEmptyName(t *testing.T) {
	f := NewFile(filepath.Join(t.TempDir(), "t.json"), 0)
	for _, bad := range []string{"", "   ", "\t\t"} {
		if _, _, err := f.Create(bad, "admin", 0); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Create(%q): expected ErrInvalidName, got %v", bad, err)
		}
	}
}

func TestRejectsOverlongName(t *testing.T) {
	f := NewFile(filepath.Join(t.TempDir(), "t.json"), 0)
	long := strings.Repeat("x", 81)
	if _, _, err := f.Create(long, "admin", 0); !errors.Is(err, ErrInvalidName) {
		t.Errorf("Create(81-char): expected ErrInvalidName, got %v", err)
	}
}

func TestValidateMissingFile(t *testing.T) {
	f := NewFile(filepath.Join(t.TempDir(), "does-not-exist.json"), 0)
	if _, ok := f.Validate("anything"); ok {
		t.Errorf("Validate on missing file: expected no match")
	}
}

func TestTokenExpiry(t *testing.T) {
	f := NewFile(filepath.Join(t.TempDir(), "tokens.json"), 0)

	rec, plain, err := f.Create("short", "admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if rec.ExpiresAt == "" {
		t.Fatal("a token with a ttl must carry an expiry")
	}
	if _, ok := f.Validate(plain); !ok {
		t.Fatal("a fresh token must validate")
	}
	if !rec.Expired(time.Now().Add(2 * time.Hour)) {
		t.Error("record must report itself expired after its ttl")
	}

	_, never, _ := f.Create("forever", "admin", 0)
	if _, ok := f.Validate(never); !ok {
		t.Error("a token without ttl must validate")
	}
	if _, _, err := f.Create("neg", "admin", -time.Second); !errors.Is(err, ErrInvalidTTL) {
		t.Errorf("negative ttl: got %v", err)
	}
	if !(Record{ExpiresAt: "garbage"}).Expired(time.Now()) {
		t.Error("an unparsable expiry must fail closed")
	}
}
