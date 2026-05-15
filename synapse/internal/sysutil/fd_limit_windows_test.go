//go:build windows

package sysutil

import "testing"

func TestRaiseFileDescriptorLimit_Windows(t *testing.T) {
	err := RaiseFileDescriptorLimit()
	if err != nil {
		t.Errorf("Expected nil error on Windows, got: %v", err)
	}
}
