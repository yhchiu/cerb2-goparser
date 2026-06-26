package app

import (
	"os"

	"cerb2-goparser/internal/clog"
	"cerb2-goparser/internal/config"
	"cerb2-goparser/internal/pop3"
)

// runPOP3 fetches messages from each configured POP3 account and processes them,
// deleting per the account's delete flag and the max_pop3_delete policy. Mirrors
// the POP3 loop in cerberus.c main.
func runPOP3(cfg *config.Config, log *clog.Logger, poster Poster) int {
	log.Log(clog.Mark, "Parser is in POP3 mode.")
	rc := ExitOK

	for _, acct := range cfg.POP3 {
		if acct.User == "" || acct.Pass == "" {
			log.Log(clog.Error, "POP3: User or Password was NULL, skipping")
			continue
		}

		c, err := pop3.Dial(log, acct.Host, acct.Port, cfg.POP3Timeout)
		if err != nil {
			log.Log(clog.Error, "POP3: could not connect to %s:%d: %v", acct.Host, acct.Port, err)
			rc = ExitSoftware
			continue
		}

		if err := c.User(acct.User); err != nil {
			log.Log(clog.Error, "POP3: %v", err)
			c.Close()
			continue
		}
		if err := c.Pass(acct.Pass); err != nil {
			log.Log(clog.Error, "POP3: %v", err)
			c.Close()
			continue
		}

		count, err := c.Stat()
		if err != nil {
			log.Log(clog.Error, "POP3: %v", err)
			_ = c.Quit()
			continue
		}

		limit := count
		if cfg.POP3Max < limit {
			limit = cfg.POP3Max
		}

		for i := 0; i < limit; i++ {
			filename, err := c.Retr(cfg.TmpMailPattern)
			if err != nil {
				log.Log(clog.Error, "POP3: RETR failed: %v", err)
				break
			}
			if filename == "" {
				break
			}

			delivered := processOne(cfg, filename, log, os.Stdout, poster)
			if !delivered {
				rc = ExitSoftware
			}

			// delete policy: always when max_pop3_delete is set, otherwise only
			// when the message was delivered successfully.
			if acct.Delete && (cfg.POP3MaxDelete || delivered) {
				if err := c.Dele(); err != nil {
					log.Log(clog.Error, "POP3: DELE failed: %v", err)
				}
			}
		}

		_ = c.Quit()
	}

	return rc
}
