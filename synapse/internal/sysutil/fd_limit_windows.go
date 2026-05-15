//go:build windows

package sysutil

// RaiseFileDescriptorLimit is a no-op on Windows since it manages handles differently.
func RaiseFileDescriptorLimit() error {
	return nil
}
