// Package app orchestrates the parser: it loads config, fetches messages (POP3
// or stdin pipe), parses each to XML, and hands them to a Poster for delivery.
// It mirrors cerberus.c main + cer_parse_files.
package app

import (
	"fmt"
	"io"
	"os"
	"strings"

	"cerb2-goparser/internal/clog"
	"cerb2-goparser/internal/config"
	"cerb2-goparser/internal/mimeparse"
	"cerb2-goparser/internal/poster"
	"cerb2-goparser/internal/xmltree"
)

// Exit codes mirror the sysexits values used by the C program.
const (
	ExitOK       = 0
	ExitUsage    = 64 // EX_USAGE
	ExitSoftware = 70 // EX_SOFTWARE
)

// Poster delivers a parsed email to the Cerberus backend. It returns whether the
// message was accepted (delivered) and any fatal error.
type Poster interface {
	Deliver(cfg *config.Config, email *xmltree.Node, log *clog.Logger) (delivered bool, err error)
}

// Main is the program entry point. args is the CLI arguments after the program
// name: [config.xml, log_level, log.txt]. It builds the real HTTP poster from
// the loaded config.
func Main(args []string, stdin io.Reader, stdout io.Writer) int {
	return run(args, stdin, stdout, nil)
}

// run executes the parser. When override is nil the real HTTP poster is built
// from config; tests pass a custom (or nil) poster via override.
func run(args []string, stdin io.Reader, stdout io.Writer, override Poster) int {
	if len(args) != 3 {
		fmt.Fprintf(os.Stderr, "\nUsage:\ncerberus xml_config_file log_level log.txt \n\n")
		return ExitUsage
	}
	configFile, levelStr, logFile := args[0], args[1], args[2]

	level := clog.GetLevel(levelStr)
	log, err := clog.Open(logFile, level)
	if err != nil {
		log.SetCallback(clog.Stderr, level)
		log.Log(clog.Error, "Could not log to file, logging to stderr!")
	}
	defer log.Close()

	log.Log(clog.Mark, "Cerberus v. 2.x build %s Starting", mimeparse.BuildNumber)

	cfg, err := config.LoadFile(configFile, log)
	if err != nil {
		log.Log(clog.Fatal, "XML: XML Config file error, shutting down. (%v)", err)
		return ExitSoftware
	}

	p := override
	if p == nil {
		p = poster.New(cfg)
	}

	exit := ExitOK
	if len(cfg.POP3) > 0 {
		exit = runPOP3(cfg, log, p)
	} else {
		log.Log(clog.Mark, "Parser is in PIPE mode, waiting for input")
		path, err := saveInput(stdin, cfg.TmpMailPattern)
		if err != nil {
			log.Log(clog.Fatal, "%v", err)
			exit = ExitSoftware
		} else {
			exit = processFiles(cfg, []string{path}, log, stdout, p)
		}
	}

	log.Log(clog.Mark, "Shutting Down")
	return exit
}

// processFiles parses and delivers each message file, returning EX_SOFTWARE if
// any message failed.
func processFiles(cfg *config.Config, files []string, log *clog.Logger, stdout io.Writer, poster Poster) int {
	rc := ExitOK
	for _, fn := range files {
		if !processOne(cfg, fn, log, stdout, poster) {
			rc = ExitSoftware
		}
	}
	return rc
}

// processOne parses one message, optionally posts it, and cleans up temp files.
// It returns true when the message was delivered (or simulated delivered in
// debug-parse mode). Mirrors the body of cer_parse_files' loop.
//
// Each message is isolated with a recover: a panic while parsing or posting one
// message is logged and treated as a failed delivery instead of aborting the
// whole batch. This restores the crash isolation the C achieved by forking a
// child process per message.
func processOne(cfg *config.Config, filename string, log *clog.Logger, stdout io.Writer, poster Poster) (ok bool) {
	var email *xmltree.Node
	delivered := false
	keyErr := false

	defer func() {
		if r := recover(); r != nil {
			log.Log(clog.Fatal, "panic while processing %s: %v", filename, r)
			delivered = false
			keyErr = true
		}
		cleanup(cfg, filename, email, delivered, keyErr)
		ok = delivered && !keyErr
	}()

	log.Log(clog.Debug, "cer_parse_files(): Processing %s", filename)

	f, err := os.Open(filename)
	if err != nil {
		log.Log(clog.Error, "could not open %s: %v", filename, err)
		return
	}
	email = mimeparse.NewParser(log, f, cfg.TmpMimePattern).FileParse()
	f.Close()

	switch {
	case cfg.DebugParse:
		if cfg.PrintXML && email != nil {
			fmt.Fprintf(stdout, "XML:\n%s\n", email.ToString())
		}
		delivered = true // simulate delivery so temp files get cleaned up

	case email == nil:
		log.Log(clog.Fatal, "Parse produced no output")

	default:
		// add the parser version and source filename for the GUI
		if e := email.Get("email"); e != nil {
			e.AddChild("parser_version").AddDataString("2.x build " + mimeparse.BuildNumber)
			e.AddChild("cerbmail").AddDataString(filename)
		}
		// decode any RFC-2047 encoded subject in place
		if subj := email.Get("email", "headers", "subject"); subj != nil {
			subj.SetData(mimeparse.ParseSubject(subj.Data))
		}

		if poster == nil {
			log.Log(clog.Warn, "No poster configured; skipping HTTP delivery")
		} else if d, perr := poster.Deliver(cfg, email, log); perr != nil {
			log.Log(clog.Fatal, "delivery error: %v", perr)
			keyErr = true
		} else {
			delivered = d
		}
	}
	return
}

// cleanup removes the attachment temp files (already uploaded) and the saved
// message file when it was delivered (or super_clean is set).
func cleanup(cfg *config.Config, filename string, email *xmltree.Node, delivered, keyErr bool) {
	var temps []string
	collectTempnames(email, &temps)
	for _, t := range temps {
		_ = os.Remove(t)
	}
	if (delivered && !keyErr) || cfg.SuperClean {
		_ = os.Remove(filename)
	}
}

func collectTempnames(n *xmltree.Node, out *[]string) {
	if n == nil {
		return
	}
	if n.Name == "tempname" && len(n.Data) > 0 {
		*out = append(*out, string(n.Data))
	}
	for _, c := range n.Children() {
		collectTempnames(c, out)
	}
}

// saveInput reads the piped message from stdin into a temp file, converting line
// endings to CRLF (cfile_pipe convert=1), and returns the temp file path.
func saveInput(stdin io.Reader, pattern string) (string, error) {
	dir, prefix := splitPattern(pattern)
	f, err := os.CreateTemp(dir, prefix+"*")
	if err != nil {
		return "", err
	}
	defer f.Close()

	data, err := io.ReadAll(stdin)
	if err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	if len(data) == 0 {
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("PIPE mode received no input from the console/pipe")
	}
	if _, err := f.Write(unixToDOS(data)); err != nil {
		return "", err
	}
	return f.Name(), nil
}

// unixToDOS expands bare \n to \r\n without doubling existing CRLF, matching
// cfile_pipe's convert=1 path.
func unixToDOS(data []byte) []byte {
	out := make([]byte, 0, len(data)+len(data)/16+1)
	var prev byte
	for _, c := range data {
		if c == '\n' && prev != '\r' {
			out = append(out, '\r')
		}
		out = append(out, c)
		prev = c
	}
	return out
}

func splitPattern(pat string) (dir, prefix string) {
	if i := strings.LastIndexAny(pat, "/\\"); i >= 0 {
		dir = pat[:i]
		prefix = pat[i+1:]
	} else {
		dir = "."
		prefix = pat
	}
	prefix = strings.TrimRight(prefix, "X")
	if prefix == "" {
		prefix = "cerbmail_"
	}
	if dir == "" {
		dir = "."
	}
	return dir, prefix
}
