package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunEmptyArgs(t *testing.T) {
	var buf bytes.Buffer
	args := []string{}
	code := Run(args, &buf)

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	out := buf.String()
	if !strings.Contains(out, "Error: Target is required") {
		t.Errorf("Expected output to contain 'Error: Target is required', got: %s", out)
	}
}

func TestRunMissingPorts(t *testing.T) {
	var buf bytes.Buffer
	args := []string{"-target", "127.0.0.1"}
	code := Run(args, &buf)

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	out := buf.String()
	if !strings.Contains(out, "Error: Ports are required") {
		t.Errorf("Expected output to contain 'Error: Ports are required', got: %s", out)
	}
}

func TestRunMissingTarget(t *testing.T) {
	var buf bytes.Buffer
	args := []string{"-ports", "80"}
	code := Run(args, &buf)

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}

	out := buf.String()
	if !strings.Contains(out, "Error: Target is required") {
		t.Errorf("Expected output to contain 'Error: Target is required', got: %s", out)
	}
}

func TestRunInvalidPort(t *testing.T) {
	var buf bytes.Buffer
	args := []string{"-target", "127.0.0.1", "-ports", "invalid"}
	code := Run(args, &buf)

	if code != 1 {
		t.Errorf("Expected exit code 1, got %d", code)
	}
}

func TestRunHelp(t *testing.T) {
	var buf bytes.Buffer
	args := []string{"-h"}
	code := Run(args, &buf)

	if code != 0 {
		t.Errorf("Expected exit code 0 for help, got %d", code)
	}

	out := buf.String()
	if !strings.Contains(out, "Usage: synapse") {
		t.Errorf("Expected output to contain 'Usage: synapse', got: %s", out)
	}
}
