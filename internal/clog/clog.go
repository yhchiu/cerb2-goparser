// Package clog is a small leveled logger ported from the C "clog" module.
//
// Levels are ordered by severity: Mark(0) is the most severe / always-shown
// marker and Trace(5) the least. A message is emitted when its level is less
// than or equal to the configured threshold (matching the original
// `level <= s_logfile_level` test in clog.c).
package clog

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Level is a log severity. Lower is more severe.
type Level int

const (
	Mark  Level = iota // 0 - non-reporting marker, always shown
	Fatal              // 1 - errors that cause the application to exit
	Error              // 2 - serious but recoverable errors
	Warn               // 3 - important warnings
	Debug              // 4 - debugging information
	Trace              // 5 - everything
)

var levelText = [...]string{"MARK ", "FATAL", "ERROR", "WARN ", "DEBUG", "TRACE"}

// String returns the fixed-width level label used in log lines.
func (l Level) String() string {
	if l < Mark || l > Trace {
		return levelText[Mark]
	}
	return levelText[l]
}

// GetLevel maps a level name to a Level using only its first character
// (M/F/E/W/D/T, case-insensitive), matching clog_getlevel. Unknown or empty
// input yields Mark.
func GetLevel(s string) Level {
	if s == "" {
		return Mark
	}
	switch s[0] {
	case 'M', 'm':
		return Mark
	case 'F', 'f':
		return Fatal
	case 'E', 'e':
		return Error
	case 'W', 'w':
		return Warn
	case 'D', 'd':
		return Debug
	case 'T', 't':
		return Trace
	default:
		return Mark
	}
}

// Logger writes leveled messages to an optional file and an optional callback,
// each with its own threshold. It mirrors the C CLOG_INFO structure.
type Logger struct {
	mu            sync.Mutex
	file          *os.File
	fileLevel     Level
	callback      func(Level, string)
	callbackLevel Level
	pid           int
}

// Open opens (and appends to) the given log file at the given threshold. If the
// file cannot be opened the returned Logger is still usable (file output stays
// disabled) and err is non-nil, so the caller can fall back to a stderr
// callback exactly as cerberus.c does.
func Open(file string, fileLevel Level) (*Logger, error) {
	l := &Logger{pid: os.Getpid()}
	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return l, err
	}
	l.file = f
	l.fileLevel = fileLevel
	return l, nil
}

// SetCallback installs a callback invoked for every message at or below level.
func (l *Logger) SetCallback(cb func(Level, string), level Level) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.callback = cb
	l.callbackLevel = level
}

// Log formats and emits a message if its level passes the file or callback
// threshold. A nil Logger is a no-op, matching the C `if(NULL==info) return`.
func (l *Logger) Log(level Level, format string, args ...any) {
	if l == nil {
		return
	}
	if level < Mark || level > Trace {
		level = Mark
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !(level <= l.fileLevel || level <= l.callbackLevel) {
		return
	}
	msg := fmt.Sprintf(format, args...)
	if l.callback != nil && level <= l.callbackLevel {
		l.callback(level, msg)
	}
	if l.file != nil && level <= l.fileLevel {
		t := time.Now()
		fmt.Fprintf(l.file, "[%d.%02d.%02d %02d:%02d:%02d %d] %s %s\n",
			t.Year(), int(t.Month()), t.Day(), t.Hour(), t.Minute(), t.Second(),
			l.pid, levelText[level], msg)
	}
}

// Close closes the underlying log file, if any.
func (l *Logger) Close() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
}

// Stderr is a ready-made callback that writes "LEVEL message" to standard error.
func Stderr(level Level, text string) {
	fmt.Fprintf(os.Stderr, "%s %s\n", level.String(), text)
}

// Stdout is a ready-made callback that writes "LEVEL message" to standard output.
func Stdout(level Level, text string) {
	fmt.Fprintf(os.Stdout, "%s %s\n", level.String(), text)
}
