package main

import (
	"os"
	"testing"
)

func TestParseSeverity(t *testing.T) {
	if s := parseSeverity("high"); s != 3 {
		t.Errorf("expected 3, got %d", s)
	}
	if s := parseSeverity("critical"); s != 4 {
		t.Errorf("expected 4, got %d", s)
	}
	if s := parseSeverity("unknown"); s != -1 {
		t.Errorf("expected -1, got %d", s)
	}
}

func TestFilterBySeverity(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test-nuclei-*.jsonl")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := `{"template-id": "test-1", "host": "1.1.1.1", "info": {"name": "Test 1", "severity": "info"}}
{"template-id": "test-2", "host": "1.1.1.1", "info": {"name": "Test 2", "severity": "medium"}}
{"template-id": "test-3", "host": "1.1.1.1", "info": {"name": "Test 3", "severity": "critical"}}
invalid json
{"template-id": "test-4", "host": "1.1.1.1", "info": {"name": "Test 4", "severity": "high"}}
`
	if err := os.WriteFile(tmpFile.Name(), []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	// Test high severity filtering
	findings, err := filterBySeverity(tmpFile.Name(), "high")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Errorf("expected 2 findings (high+critical), got %d", len(findings))
	}
	if len(findings) > 0 && findings[0].TemplateID != "test-3" {
		t.Errorf("expected test-3, got %s", findings[0].TemplateID)
	}

	// Test missing file
	findings, err = filterBySeverity("non-existent-file.jsonl", "high")
	if err != nil {
		t.Fatalf("unexpected error for non-existent file: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-existent file, got %d", len(findings))
	}

	// Test low severity filtering
	findings, err = filterBySeverity(tmpFile.Name(), "low")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Errorf("expected 3 findings, got %d", len(findings))
	}
}
