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
	defer tempStdout.Close()

	tempFile, err := os.CreateTemp("", "output-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

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

	tempFile, err := os.CreateTemp("", "output-json-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	w, err := NewWriter(tempFile.Name(), true, false)
	if err != nil {
		t.Fatal(err)
	}

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
	defer tempStdout.Close()

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

func TestWriter_Log(t *testing.T) {
	tests := []struct {
		name     string
		quiet    bool
		format   string
		args     []interface{}
		expected string
	}{
		{
			name:     "Log writes to stdout when not quiet",
			quiet:    false,
			format:   "Test log message %d",
			args:     []interface{}{1},
			expected: "Test log message 1\n",
		},
		{
			name:     "Log does not write to stdout when quiet",
			quiet:    true,
			format:   "Test log message %d",
			args:     []interface{}{2},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempStdout, err := os.CreateTemp("", "stdout-log-*")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(tempStdout.Name())
			defer tempStdout.Close()
			defer tempStdout.Close()

			w := &Writer{
				quiet: tt.quiet,
				out:   tempStdout,
			}

			w.Log(tt.format, tt.args...)

			stdoutContent, err := os.ReadFile(tempStdout.Name())
			if err != nil {
				t.Fatal(err)
			}
			if string(stdoutContent) != tt.expected {
				t.Errorf("Log output = %q, want %q", string(stdoutContent), tt.expected)
			}
		})
	}
}
