package main

import (
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
