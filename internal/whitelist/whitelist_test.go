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

func TestAddRemoveAndListArePersisted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	write(t, path, "alice@example.com\n")

	f := New(path, 0)
	if err := f.Add("bob@example.com"); err != nil {
		t.Fatalf("Add bob: %v", err)
	}
	if err := f.Add("bob@example.com"); err != nil {
		t.Fatalf("Add bob (idempotent): %v", err)
	}

	// Re-open to make sure it really landed on disk.
	f2 := New(path, 0)
	list := f2.List()
	want := []string{"alice@example.com", "bob@example.com"}
	if !equalSlices(list, want) {
		t.Fatalf("List after add: got %v, want %v", list, want)
	}

	if err := f.Remove("alice@example.com"); err != nil {
		t.Fatalf("Remove alice: %v", err)
	}
	if err := f.Remove("alice@example.com"); err != nil {
		t.Fatalf("Remove alice (idempotent): %v", err)
	}

	f3 := New(path, 0)
	list = f3.List()
	if !equalSlices(list, []string{"bob@example.com"}) {
		t.Fatalf("List after remove: got %v", list)
	}
}

func TestAddRejectsBogusEmails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	write(t, path, "")

	f := New(path, 0)
	for _, bad := range []string{"", "   ", "no-at-sign", "@no-local", "user@", "a@b", "two@@ats.com", "has space@x.y"} {
		if err := f.Add(bad); err == nil {
			t.Errorf("Add(%q): expected error, got nil", bad)
		}
	}
}

func TestRemoveOnEmptyFileNoop(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	write(t, path, "")

	f := New(path, 0)
	if err := f.Remove("nobody@example.com"); err != nil {
		t.Errorf("Remove on empty: %v", err)
	}
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
