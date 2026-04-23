// Package whitelist loads the authorized-emails file on demand and caches it
// briefly, so operators can edit the file without restarting the proxy.
package whitelist

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Checker answers "is this email allowed to log in".
type Checker interface {
	Allowed(email string) bool
}

// Store extends Checker with admin-level add/remove/list operations used by
// the web UI at /auth/admin.
type Store interface {
	Checker
	List() []string
	Add(email string) error
	Remove(email string) error
}

// ErrInvalidEmail is returned by Add when the argument isn't syntactically
// a reasonable email address (missing '@', empty, whitespace-only, …).
var ErrInvalidEmail = errors.New("invalid email")

// File reads a newline-delimited file of lowercase emails.
// Lines starting with "#" and blank lines are ignored.
// The file is re-read every refreshAfter to pick up edits (e.g. via sed or Ansible);
// lookups never block on disk I/O outside the refresh window.
type File struct {
	path         string
	refreshAfter time.Duration

	mu       sync.RWMutex
	loaded   time.Time
	allowed  map[string]struct{}
	loadErr  error
}

// New returns a File that re-reads path at most every refreshAfter.
// Pass refreshAfter=0 to re-read on every lookup (useful in tests).
func New(path string, refreshAfter time.Duration) *File {
	return &File{path: path, refreshAfter: refreshAfter}
}

// Allowed reports whether the email is present in the whitelist.
// Matching is case-insensitive and whitespace-trimmed.
func (f *File) Allowed(email string) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return false
	}
	f.refreshIfStale()

	f.mu.RLock()
	defer f.mu.RUnlock()
	_, ok := f.allowed[email]
	return ok
}

// LastError returns the most recent load error, or nil if the last load
// succeeded. Useful for /healthz reporting.
func (f *File) LastError() error {
	f.refreshIfStale()
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.loadErr
}

// Size returns the number of whitelist entries after the most recent successful load.
func (f *File) Size() int {
	f.refreshIfStale()
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.allowed)
}

// List returns the whitelist sorted alphabetically.
func (f *File) List() []string {
	f.refreshIfStale()
	f.mu.RLock()
	defer f.mu.RUnlock()

	out := make([]string, 0, len(f.allowed))
	for e := range f.allowed {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

// Add appends an email to the whitelist file and to the in-memory set.
// The operation is idempotent: adding an existing email is a no-op.
// The argument is lowercased and whitespace-trimmed before validation.
func (f *File) Add(email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if !plausibleEmail(email) {
		return ErrInvalidEmail
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.allowed == nil {
		// Cold start; load once before we start mutating.
		set, err := parseFile(f.path)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("load whitelist: %w", err)
		}
		if set == nil {
			set = make(map[string]struct{})
		}
		f.allowed = set
		f.loaded = time.Now()
	}
	if _, exists := f.allowed[email]; exists {
		return nil
	}

	if err := appendLine(f.path, email); err != nil {
		return fmt.Errorf("append to %s: %w", f.path, err)
	}
	f.allowed[email] = struct{}{}
	f.loaded = time.Now()
	return nil
}

// Remove drops an email from the whitelist. Idempotent — removing a non-member
// is not an error. The on-disk file is rewritten atomically (write-tmp +
// rename) so readers never see a partial state.
func (f *File) Remove(email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return ErrInvalidEmail
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.allowed == nil {
		set, err := parseFile(f.path)
		if err != nil {
			return fmt.Errorf("load whitelist: %w", err)
		}
		f.allowed = set
		f.loaded = time.Now()
	}
	if _, exists := f.allowed[email]; !exists {
		return nil
	}

	remaining := make([]string, 0, len(f.allowed)-1)
	for e := range f.allowed {
		if e != email {
			remaining = append(remaining, e)
		}
	}
	sort.Strings(remaining)
	if err := rewriteFile(f.path, remaining); err != nil {
		return fmt.Errorf("rewrite %s: %w", f.path, err)
	}
	delete(f.allowed, email)
	f.loaded = time.Now()
	return nil
}

// plausibleEmail is a deliberately-lenient check: must contain exactly one
// "@", have a non-empty local part and a domain with at least one dot. We
// don't try to enforce RFC 5321 — the authoritative gate is whether Yandex
// issues a token for this email, not our regex.
func plausibleEmail(s string) bool {
	if s == "" {
		return false
	}
	at := strings.IndexByte(s, '@')
	if at <= 0 || at == len(s)-1 {
		return false
	}
	if strings.IndexByte(s[at+1:], '@') >= 0 {
		return false
	}
	if !strings.Contains(s[at+1:], ".") {
		return false
	}
	for _, r := range s {
		if r <= ' ' {
			return false
		}
	}
	return true
}

// appendLine opens the file for O_APPEND and writes `line + "\n"`. Creates
// the file (with mode 0644) if it does not yet exist.
func appendLine(path, line string) error {
	fh, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer fh.Close()
	_, err = fmt.Fprintln(fh, line)
	return err
}

// rewriteFile writes `lines` (plus trailing newline each) to a temp file in the
// same directory, syncs, and renames over the target — atomic on POSIX.
func rewriteFile(path string, lines []string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".whitelist-*")
	if err != nil {
		return err
	}
	defer func() {
		// Best-effort cleanup if rename failed.
		_ = os.Remove(tmp.Name())
	}()
	for _, l := range lines {
		if _, err := fmt.Fprintln(tmp, l); err != nil {
			tmp.Close()
			return err
		}
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (f *File) refreshIfStale() {
	f.mu.RLock()
	if f.refreshAfter > 0 && time.Since(f.loaded) < f.refreshAfter && f.allowed != nil {
		f.mu.RUnlock()
		return
	}
	f.mu.RUnlock()

	f.mu.Lock()
	defer f.mu.Unlock()
	// Re-check after acquiring the write lock (another goroutine may have loaded).
	if f.refreshAfter > 0 && time.Since(f.loaded) < f.refreshAfter && f.allowed != nil {
		return
	}

	set, err := parseFile(f.path)
	f.loaded = time.Now()
	f.loadErr = err
	if err != nil && f.allowed != nil {
		// Keep serving the previous list on transient read errors.
		return
	}
	f.allowed = set
}

func parseFile(path string) (map[string]struct{}, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()

	out := make(map[string]struct{}, 32)
	scanner := bufio.NewScanner(fh)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[strings.ToLower(line)] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
