package imapstate

import (
	"path/filepath"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")

	s, err := Load(path) // missing file -> empty
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Mailboxes) != 0 {
		t.Fatalf("expected empty state, got %d entries", len(s.Mailboxes))
	}

	s.Put("box1", 42, map[int]bool{3: true, 1: true, 2: true})
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	s2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	got := s2.Processed("box1", 42)
	if len(got) != 3 || !got[1] || !got[2] || !got[3] {
		t.Errorf("processed = %v, want {1,2,3}", got)
	}
	// UIDVALIDITY mismatch discards the stored UIDs
	if n := len(s2.Processed("box1", 99)); n != 0 {
		t.Errorf("uidvalidity mismatch returned %d uids, want 0", n)
	}
	// unknown mailbox key is empty
	if n := len(s2.Processed("other", 42)); n != 0 {
		t.Errorf("unknown key returned %d uids, want 0", n)
	}
}

func TestLoadMissing(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("Load missing: %v", err)
	}
	if s == nil || len(s.Mailboxes) != 0 {
		t.Errorf("want usable empty state, got %+v", s)
	}
}
