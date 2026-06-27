package app

import (
	"crypto/tls"
	"fmt"
	"os"

	"cerb2-goparser/internal/clog"
	"cerb2-goparser/internal/config"
	"cerb2-goparser/internal/imap"
	"cerb2-goparser/internal/imapstate"
)

// runIMAP fetches messages from each configured IMAP account and processes them,
// marking messages \Deleted by UID per the account's delete flag and the
// max_pop3_delete policy, then expunging once per account. The max_pop3_messages
// and pop3_timeout settings apply to IMAP as well.
//
// When global/imap_state is configured, processed UIDs are remembered per
// mailbox (keyed by UIDVALIDITY) so already-handled messages are skipped on
// later runs — useful when delete is false.
func runIMAP(cfg *config.Config, log *clog.Logger, poster Poster) int {
	log.Log(clog.Mark, "Parser is in IMAP mode.")
	rc := ExitOK

	var state *imapstate.State
	if cfg.IMAPStateFile != "" {
		s, err := imapstate.Load(cfg.IMAPStateFile)
		if err != nil {
			log.Log(clog.Error, "IMAP: could not read state file %s: %v", cfg.IMAPStateFile, err)
		}
		state = s // Load returns a usable empty state even on error
	}

	for _, acct := range cfg.IMAP {
		if !runIMAPAccount(cfg, acct, state, log, poster) {
			rc = ExitSoftware
		}
	}

	if state != nil {
		if err := state.Save(); err != nil {
			log.Log(clog.Error, "IMAP: could not save state file %s: %v", cfg.IMAPStateFile, err)
		}
	}
	return rc
}

// runIMAPAccount processes one account and returns false if anything failed.
func runIMAPAccount(cfg *config.Config, acct config.IMAPAccount, state *imapstate.State, log *clog.Logger, poster Poster) (ok bool) {
	ok = true
	if acct.User == "" || acct.Pass == "" {
		log.Log(clog.Error, "IMAP: User or Password was empty, skipping")
		return false
	}

	// implicit TLS connects over TLS; STARTTLS connects plaintext then upgrades.
	var dialTLS *tls.Config
	if acct.TLS {
		dialTLS = config.TLSConfig(cfg)
	}

	c, err := imap.Dial(log, acct.Host, acct.Port, cfg.POP3Timeout, dialTLS)
	if err != nil {
		log.Log(clog.Error, "IMAP: could not connect to %s:%d: %v", acct.Host, acct.Port, err)
		return false
	}
	defer c.Logout()

	if acct.STARTTLS {
		if err := c.StartTLS(config.TLSConfig(cfg)); err != nil {
			log.Log(clog.Error, "IMAP: STARTTLS failed: %v", err)
			return false
		}
	}
	if err := c.Login(acct.User, acct.Pass); err != nil {
		log.Log(clog.Error, "IMAP: %v", err)
		return false
	}
	if _, err := c.Select(acct.Mailbox, acct.Search); err != nil {
		log.Log(clog.Error, "IMAP: %v", err)
		return false
	}

	candidates := c.UIDs()

	// dedup: skip UIDs already processed in a prior run, and start the new
	// processed set from the prior one pruned to UIDs still on the server.
	var processed, newProcessed map[int]bool
	key := stateKey(acct)
	if state != nil {
		processed = state.Processed(key, c.UIDValidity())

		serverAll := candidates
		if acct.Search != "ALL" {
			if all, err := c.SearchAllUIDs(); err == nil {
				serverAll = all
			}
		}
		present := make(map[int]bool, len(serverAll))
		for _, u := range serverAll {
			present[u] = true
		}
		newProcessed = make(map[int]bool, len(processed))
		for u := range processed {
			if present[u] {
				newProcessed[u] = true
			}
		}
	}

	var toFetch []int
	for _, uid := range candidates {
		if processed == nil || !processed[uid] {
			toFetch = append(toFetch, uid)
		}
	}
	limit := len(toFetch)
	if cfg.POP3Max < limit {
		limit = cfg.POP3Max
	}

	deleted := false
	for i := 0; i < limit; i++ {
		uid := toFetch[i]
		filename, err := c.FetchUID(uid, cfg.TmpMailPattern)
		if err != nil {
			log.Log(clog.Error, "IMAP: UID FETCH %d failed: %v", uid, err)
			ok = false
			break
		}
		if filename == "" {
			continue
		}

		delivered := processOne(cfg, filename, log, os.Stdout, poster)
		if !delivered {
			ok = false
		} else if newProcessed != nil {
			newProcessed[uid] = true
		}

		if acct.Delete && (cfg.POP3MaxDelete || delivered) {
			if err := c.Delete(); err != nil {
				log.Log(clog.Error, `IMAP: UID STORE \Deleted failed: %v`, err)
			} else {
				deleted = true
			}
		}
	}
	if deleted {
		if err := c.Expunge(); err != nil {
			log.Log(clog.Error, "IMAP: EXPUNGE failed: %v", err)
		}
	}

	if state != nil {
		state.Put(key, c.UIDValidity(), newProcessed)
	}
	return ok
}

func stateKey(a config.IMAPAccount) string {
	return fmt.Sprintf("%s:%d|%s|%s", a.Host, a.Port, a.User, a.Mailbox)
}
