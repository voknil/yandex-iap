package session

import (
	"strings"
	"testing"
	"time"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func TestIssueVerifyRoundTrip(t *testing.T) {
	tok, err := Issue(testKey, "user@example.com", "User Name", time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	p, err := Verify(testKey, tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if p.Email != "user@example.com" {
		t.Errorf("email: got %q", p.Email)
	}
	if p.Name != "User Name" {
		t.Errorf("name: got %q", p.Name)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	tok, _ := Issue(testKey, "user@example.com", "", time.Minute)
	// Flip one character in the payload half.
	parts := strings.SplitN(tok, ".", 2)
	tampered := parts[0][:len(parts[0])-1] + "X" + "." + parts[1]
	if _, err := Verify(testKey, tampered); err != ErrInvalid {
		t.Errorf("expected ErrInvalid, got %v", err)
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	tok, _ := Issue(testKey, "user@example.com", "", time.Minute)
	parts := strings.SplitN(tok, ".", 2)
	// Flip a bit in the *first* byte of the signature. Base64 encodes 6 bits
	// per character, so for a 32-byte HMAC the last character only carries
	// 2 significant bits (the other 4 are padding and round-trip cleanly
	// through RawURLEncoding). Editing the first byte guarantees the
	// decoded signature changes.
	b := []byte(parts[1])
	b[0] ^= 0x01
	tampered := parts[0] + "." + string(b)
	if _, err := Verify(testKey, tampered); err != ErrInvalid {
		t.Errorf("expected ErrInvalid, got %v", err)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	tok, _ := Issue(testKey, "user@example.com", "", -time.Second)
	if _, err := Verify(testKey, tok); err != ErrInvalid {
		t.Errorf("expected ErrInvalid for expired token, got %v", err)
	}
}

func TestVerifyRejectsForeignKey(t *testing.T) {
	tok, _ := Issue(testKey, "user@example.com", "", time.Minute)
	other := []byte("00000000000000000000000000000000")
	if _, err := Verify(other, tok); err != ErrInvalid {
		t.Errorf("expected ErrInvalid with different key, got %v", err)
	}
}

func TestStateRoundTrip(t *testing.T) {
	s, err := SignState(testKey, "https://example.org/dashboard", time.Minute)
	if err != nil {
		t.Fatalf("SignState: %v", err)
	}
	rd, err := VerifyState(testKey, s)
	if err != nil {
		t.Fatalf("VerifyState: %v", err)
	}
	if rd != "https://example.org/dashboard" {
		t.Errorf("redirect: got %q", rd)
	}
}

func TestStateRejectsExpired(t *testing.T) {
	s, _ := SignState(testKey, "/", -time.Second)
	if _, err := VerifyState(testKey, s); err != ErrInvalid {
		t.Errorf("expected ErrInvalid, got %v", err)
	}
}

func TestStateRejectsTampering(t *testing.T) {
	s, _ := SignState(testKey, "/", time.Minute)
	parts := strings.SplitN(s, ".", 2)
	b := []byte(parts[1])
	b[0] ^= 0x01
	tampered := parts[0] + "." + string(b)
	if _, err := VerifyState(testKey, tampered); err != ErrInvalid {
		t.Errorf("expected ErrInvalid, got %v", err)
	}
}
