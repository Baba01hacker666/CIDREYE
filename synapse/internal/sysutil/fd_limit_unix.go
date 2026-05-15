//go:build !windows

package sysutil

import (
	"syscall"
)

// RaiseFileDescriptorLimit attempts to raise the open file descriptor limit
// to the maximum hard limit allowed by the OS.
func RaiseFileDescriptorLimit() error {
	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
		return err
	}

	// Set soft limit to hard limit
	rLimit.Cur = rLimit.Max
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
		return err
	}

	return nil
}
