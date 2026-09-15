package wisp

import (
	"log"
	"strings"
)

const (
	levelDebug int = iota
	levelInfo
	levelWarn
	levelError
	levelNone
)

func newLogger(level string) Logger {
	lvl := levelInfo
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		lvl = levelDebug
	case "info":
		lvl = levelInfo
	case "warn", "warning":
		lvl = levelWarn
	case "error":
		lvl = levelError
	case "none":
		lvl = levelNone
	}
	return &Log{level: lvl, inner: log.Default()}
}

func (l *Log) Debug(msg string, keyValuePairs ...any) {
	if l == nil || l.inner == nil || levelDebug < l.level {
		return
	}
	l.log("DEBUG", msg, keyValuePairs)
}
func (l *Log) Info(msg string, keyValuePairs ...any) {
	if l == nil || l.inner == nil || levelInfo < l.level {
		return
	}
	l.log("INFO", msg, keyValuePairs)
}
func (l *Log) Warn(msg string, keyValuePairs ...any) {
	if l == nil || l.inner == nil || levelWarn < l.level {
		return
	}
	l.log("WARN", msg, keyValuePairs)
}
func (l *Log) Error(msg string, keyValuePairs ...any) {
	if l == nil || l.inner == nil || levelError < l.level {
		return
	}
	l.log("ERROR", msg, keyValuePairs)
}

func (l *Log) log(prefix string, msg string, kv []any) {
	if len(kv) == 0 {
		l.inner.Printf("[%s] %s", prefix, msg)
		return
	}
	l.inner.Printf("[%s] %s %v", prefix, msg, kv)
}
