package whitelist

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestBasicAllowAndDeny(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	write(t, path, "alice@example.com\n# bob is out\nCharlie@Example.COM\n")

	f := New(path, 0)
	if !f.Allowed("alice@example.com") {
		t.Error("alice should be allowed")
	}
	if !f.Allowed("ALICE@example.COM") {
		t.Error("matching is case-insensitive")
	}
	if !f.Allowed("charlie@example.com") {
		t.Error("case-folded entries should match")
	}
	if f.Allowed("bob@example.com") {
		t.Error("commented-out entry must not match")
	}
	if f.Allowed("") {
		t.Error("empty email must not match")
	}
}

func TestHotReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	write(t, path, "alice@example.com\n")

	f := New(path, 0) // 0 -> reload on every lookup
	if f.Allowed("dan@example.com") {
		t.Fatalf("dan not allowed yet")
	}
	write(t, path, "alice@example.com\ndan@example.com\n")
	if !f.Allowed("dan@example.com") {
		t.Fatalf("dan should be allowed after file edit")
	}
}

func TestKeepsPrevListOnTransientReadError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	write(t, path, "alice@example.com\n")

	f := New(path, 0)
	if !f.Allowed("alice@example.com") {
		t.Fatalf("seed allowed")
	}
	// Move the file away to simulate a failed read.
	os.Rename(path, path+".gone")
	time.Sleep(5 * time.Millisecond)
	// The cached list should keep answering.
	if !f.Allowed("alice@example.com") {
		t.Errorf("previous list should still serve after read error")
	}
	if f.LastError() == nil {
		t.Errorf("LastError should be populated after a failed read")
	}
}

func TestSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	write(t, path, "a@x\nb@x\n#c@x\n\nd@x\n")

	f := New(path, 0)
	if n := f.Size(); n != 3 {
		t.Errorf("Size: got %d, want 3", n)
	}
}
