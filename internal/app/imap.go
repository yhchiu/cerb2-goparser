package app

import (
	"crypto/tls"
	"os"

	"cerb2-goparser/internal/clog"
	"cerb2-goparser/internal/config"
	"cerb2-goparser/internal/imap"
)

// runIMAP fetches messages from each configured IMAP account and processes them,
// marking messages \Deleted per the account's delete flag and the
// max_pop3_delete policy, then expunging once per account. The max_pop3_messages
// and pop3_timeout settings apply to IMAP as well.
func runIMAP(cfg *config.Config, log *clog.Logger, poster Poster) int {
	log.Log(clog.Mark, "Parser is in IMAP mode.")
	rc := ExitOK

	for _, acct := range cfg.IMAP {
		if acct.User == "" || acct.Pass == "" {
			log.Log(clog.Error, "IMAP: User or Password was empty, skipping")
			continue
		}

		// implicit TLS connects over TLS; STARTTLS connects plaintext and
		// upgrades. Both honor the ssl verification settings.
		var dialTLS *tls.Config
		if acct.TLS {
			dialTLS = config.TLSConfig(cfg)
		}

		c, err := imap.Dial(log, acct.Host, acct.Port, cfg.POP3Timeout, dialTLS)
		if err != nil {
			log.Log(clog.Error, "IMAP: could not connect to %s:%d: %v", acct.Host, acct.Port, err)
			rc = ExitSoftware
			continue
		}

		if acct.STARTTLS {
			if err := c.StartTLS(config.TLSConfig(cfg)); err != nil {
				log.Log(clog.Error, "IMAP: STARTTLS failed: %v", err)
				c.Close()
				continue
			}
		}

		if err := c.Login(acct.User, acct.Pass); err != nil {
			log.Log(clog.Error, "IMAP: %v", err)
			c.Close()
			continue
		}

		count, err := c.Select(acct.Mailbox, acct.Search)
		if err != nil {
			log.Log(clog.Error, "IMAP: %v", err)
			_ = c.Logout()
			continue
		}

		limit := count
		if cfg.POP3Max < limit {
			limit = cfg.POP3Max
		}

		deleted := false
		for i := 0; i < limit; i++ {
			filename, err := c.Fetch(cfg.TmpMailPattern)
			if err != nil {
				log.Log(clog.Error, "IMAP: FETCH failed: %v", err)
				break
			}
			if filename == "" {
				break
			}

			delivered := processOne(cfg, filename, log, os.Stdout, poster)
			if !delivered {
				rc = ExitSoftware
			}

			// delete policy matches POP3: always when max_pop3_delete is set,
			// otherwise only when the message was delivered. EXPUNGE happens once
			// after the loop so sequence numbers stay stable while fetching.
			if acct.Delete && (cfg.POP3MaxDelete || delivered) {
				if err := c.Delete(); err != nil {
					log.Log(clog.Error, `IMAP: STORE \Deleted failed: %v`, err)
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
		_ = c.Logout()
	}

	return rc
}
