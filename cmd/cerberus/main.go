// Command cerberus is the Go port of the Cerberus 2 CLI email parser.
//
// Usage:
//
//	cerberus <xml_config_file> <log_level> <log.txt>
//
// With a <pop3> section in the config it fetches and parses mail from each
// account; otherwise it reads one message from stdin (pipe mode). Parsed
// messages are posted to the configured Cerberus parser endpoint.
package main

import (
	"os"

	"cerb2-goparser/internal/app"
)

func main() {
	os.Exit(app.Main(os.Args[1:], os.Stdin, os.Stdout))
}
