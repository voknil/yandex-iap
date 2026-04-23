// Package whitelist loads the authorized-emails file on demand and caches it
// briefly, so operators can edit the file without restarting the proxy.
package whitelist

import (
	"bufio"
	"os"
	"strings"
	"sync"
	"time"
)

// Checker answers "is this email allowed to log in".
type Checker interface {
	Allowed(email string) bool
}

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
