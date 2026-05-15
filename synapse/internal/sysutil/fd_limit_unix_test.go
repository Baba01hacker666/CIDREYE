//go:build !windows

package sysutil

import (
	"syscall"
	"testing"
)

func TestRaiseFileDescriptorLimit_Unix(t *testing.T) {
	err := RaiseFileDescriptorLimit()
	if err != nil {
		t.Logf("Failed to raise limit (expected in some sandboxed environments): %v", err)
		return
	}

	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
		t.Fatalf("Getrlimit failed: %v", err)
	}

	if rLimit.Cur != rLimit.Max {
		t.Errorf("Expected current limit to be equal to max limit, got Cur: %v, Max: %v", rLimit.Cur, rLimit.Max)
	}
}
