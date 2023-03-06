// Package internal contains internal implementation details.
package internal

import "github.com/bassosimone/netem"

// NullLogger is a [netem.Logger] that does not emit logs.
type NullLogger struct{}

// Debug implements netem.Logger
func (nl *NullLogger) Debug(message string) {
	// nothing
}

// Debugf implements netem.Logger
func (nl *NullLogger) Debugf(format string, v ...any) {
	// nothing
}

// Info implements netem.Logger
func (nl *NullLogger) Info(message string) {
	// nothing
}

// Infof implements netem.Logger
func (nl *NullLogger) Infof(format string, v ...any) {
	// nothing
}

// Warn implements netem.Logger
func (nl *NullLogger) Warn(message string) {
	// nothing
}

// Warnf implements netem.Logger
func (nl *NullLogger) Warnf(format string, v ...any) {
	// nothing
}

var _ netem.Logger = &NullLogger{}
