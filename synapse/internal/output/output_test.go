package output

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestWriter_WriteResult(t *testing.T) {
	// Create a temporary file to capture standard out for the test
	tempStdout, err := os.CreateTemp("", "stdout-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tempStdout.Name())

	tempFile, err := os.CreateTemp("", "output-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tempFile.Name())

	w, err := NewWriter(tempFile.Name(), false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	// Override stdout
	w.out = tempStdout

	r := Result{IP: "127.0.0.1", Port: 80, State: "OPEN"}
	if err := w.WriteResult(r); err != nil {
		t.Errorf("WriteResult() error = %v", err)
	}

	w.Close()

	// check file content
	content, err := os.ReadFile(tempFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	expected := "127.0.0.1:80 [OPEN]\n"
	if string(content) != expected {
		t.Errorf("File content = %q, want %q", string(content), expected)
	}

	// check stdout content
	stdoutContent, err := os.ReadFile(tempStdout.Name())
	if err != nil {
		t.Fatal(err)
	}
	if string(stdoutContent) != expected {
		t.Errorf("Stdout content = %q, want %q", string(stdoutContent), expected)
	}
}

func TestWriter_WriteResultJSON(t *testing.T) {
	var buf bytes.Buffer

	w := &Writer{
		json:  true,
		quiet: false,
		out:   nil, // Mocked with buffer via an interface if we could, but here we just assign to an os.File mock?
	}

	// Instead of mocking w.out which is os.File, just use file output to test JSON
	tempFile, err := os.CreateTemp("", "output-json-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tempFile.Name())

	w.file = tempFile

	r := Result{IP: "127.0.0.1", Port: 80, State: "OPEN", Banner: "HTTP/1.1"}

	// Temporarily redirect w.out to avoid stdout spam during test, or just set quiet=true
	w.quiet = true

	if err := w.WriteResult(r); err != nil {
		t.Errorf("WriteResult() error = %v", err)
	}
	w.Close()

	content, err := os.ReadFile(tempFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	expected := `{"ip":"127.0.0.1","port":80,"state":"OPEN","banner":"HTTP/1.1"}` + "\n"
	if string(content) != expected {
		t.Errorf("JSON output = %q, want %q", string(content), expected)
	}
	_ = buf
}

func TestWriter_Quiet(t *testing.T) {
	tempStdout, err := os.CreateTemp("", "stdout-quiet-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tempStdout.Name())

	w := &Writer{
		json:  false,
		quiet: true,
		out:   tempStdout,
	}

	r := Result{IP: "127.0.0.1", Port: 80, State: "OPEN"}
	if err := w.WriteResult(r); err != nil {
		t.Errorf("WriteResult() error = %v", err)
	}

	stdoutContent, err := os.ReadFile(tempStdout.Name())
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.TrimSpace(string(stdoutContent))) != 0 {
		t.Errorf("Stdout should be empty when quiet is true, got: %q", string(stdoutContent))
	}
}
