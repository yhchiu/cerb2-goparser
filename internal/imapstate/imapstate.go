// Package imapstate persists, per mailbox, the set of IMAP UIDs already
// processed so messages are not re-fetched across runs. State is keyed by a
// caller-supplied mailbox key and guarded by UIDVALIDITY: if the server's
// UIDVALIDITY changes, the stored UIDs for that mailbox are treated as empty
// (the mailbox was recreated and old UIDs are meaningless).
package imapstate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

type mailbox struct {
	UIDValidity uint32 `json:"uidvalidity"`
	UIDs        []int  `json:"uids"`
}

// State is the on-disk dedup state. Use Load to read it and Save to persist.
type State struct {
	path      string
	Version   int                `json:"version"`
	Mailboxes map[string]mailbox `json:"mailboxes"`
}

// Load reads the state file at path. A missing or empty file yields a usable
// empty State (with the path set) and no error.
func Load(path string) (*State, error) {
	s := &State{path: path, Version: 1, Mailboxes: map[string]mailbox{}}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return s, err
	}
	if len(data) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(data, s); err != nil {
		return s, err
	}
	if s.Mailboxes == nil {
		s.Mailboxes = map[string]mailbox{}
	}
	return s, nil
}

// Processed returns the set of processed UIDs for key, but only when the stored
// UIDVALIDITY matches uidValidity; otherwise an empty set.
func (s *State) Processed(key string, uidValidity uint32) map[int]bool {
	set := map[int]bool{}
	if mb, ok := s.Mailboxes[key]; ok && mb.UIDValidity == uidValidity {
		for _, u := range mb.UIDs {
			set[u] = true
		}
	}
	return set
}

// Put records the processed UID set for key under uidValidity, replacing any
// previous entry.
func (s *State) Put(key string, uidValidity uint32, uids map[int]bool) {
	list := make([]int, 0, len(uids))
	for u := range uids {
		list = append(list, u)
	}
	sort.Ints(list)
	if s.Mailboxes == nil {
		s.Mailboxes = map[string]mailbox{}
	}
	s.Mailboxes[key] = mailbox{UIDValidity: uidValidity, UIDs: list}
}

// Save atomically writes the state to its file (temp file + rename). It is a
// no-op if the State has no path.
func (s *State) Save() error {
	if s.path == "" {
		return nil
	}
	s.Version = 1
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".imapstate-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, s.path)
}
