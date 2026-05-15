# Scanner Optimizations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve scanner performance and service detection by raising file descriptor limits automatically and implementing active protocol probes.

**Architecture:** Create a `sysutil` package to handle OS-specific syscalls for raising `ulimit` at startup. Enhance the `grabBanner` function in the scanner to use a two-phase approach: passive read, followed by an active HTTP GET probe if the passive read fails.

**Tech Stack:** Go (Standard Library, `syscall` package)

---

### Task 1: Automatic File Descriptor Limits

**Files:**
- Create: `synapse/internal/sysutil/fd_limit_unix.go`
- Create: `synapse/internal/sysutil/fd_limit_windows.go`
- Modify: `synapse/cmd/synapse/main.go`

- [ ] **Step 1: Create the Windows fallback implementation**

Create `synapse/internal/sysutil/fd_limit_windows.go`:
```go
//go:build windows

package sysutil

// RaiseFileDescriptorLimit is a no-op on Windows since it manages handles differently.
func RaiseFileDescriptorLimit() error {
	return nil
}
```

- [ ] **Step 2: Create the Unix implementation**

Create `synapse/internal/sysutil/fd_limit_unix.go`:
```go
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
```

- [ ] **Step 3: Call the function in main.go**

Modify `synapse/cmd/synapse/main.go`. Add the import and call it at the start of `main()`:

```go
import (
	// ... existing imports ...
	"synapse/internal/sysutil"
)

func main() {
	// Try to raise FD limits at the very start to support high concurrency
	_ = sysutil.RaiseFileDescriptorLimit()

	var (
		configFile        string
// ... rest of main ...
```

- [ ] **Step 4: Verify the build passes**

Run: `cd synapse && go build ./cmd/synapse`
Expected: Successful build, no compilation errors.

- [ ] **Step 5: Commit**

```bash
git add synapse/internal/sysutil synapse/cmd/synapse/main.go
git commit -m "feat(sysutil): automatically raise file descriptor limits at startup"
```

### Task 2: Active Protocol Probes (Banner Grabbing)

**Files:**
- Modify: `synapse/internal/scanner/scanner.go`
- Modify: `synapse/internal/scanner/scanner_test.go`

- [ ] **Step 1: Write the failing test**

In `synapse/internal/scanner/scanner_test.go`, add a test for active probing.

```go
func TestGrabBannerActiveProbe(t *testing.T) {
	// Create a local TCP server that requires an HTTP GET before responding
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		
		// Read the probe
		buf := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _ := conn.Read(buf)
		
		if strings.HasPrefix(string(buf[:n]), "GET / HTTP/1.0") {
			conn.Write([]byte("HTTP/1.1 200 OK\r\nServer: CustomHTTP\r\n\r\n"))
		}
	}()

	// Connect as a client and test grabBanner
	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	banner := grabBanner(conn, 2*time.Second)
	if !strings.Contains(banner, "CustomHTTP") {
		t.Errorf("Expected banner to contain 'CustomHTTP', got: %s", banner)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd synapse && go test ./internal/scanner -run TestGrabBannerActiveProbe`
Expected: FAIL (because the current `grabBanner` just reads passively and will time out since the test server waits for the GET request).

- [ ] **Step 3: Update `grabBanner` implementation**

In `synapse/internal/scanner/scanner.go`, update `grabBanner` to use the two-phase approach:

```go
func grabBanner(conn net.Conn, timeout time.Duration) string {
	// Phase 1: Passive read (wait for server to speak first)
	// We split the timeout in half for the passive read
	passiveTimeout := timeout / 2
	conn.SetReadDeadline(time.Now().Add(passiveTimeout))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	
	if err == nil && n > 0 {
		return cleanBanner(string(buf[:n]))
	}

	// Phase 2: Active probe
	// If passive read timed out or failed, send an HTTP GET probe
	probe := []byte("GET / HTTP/1.0\r\n\r\n")
	conn.SetWriteDeadline(time.Now().Add(passiveTimeout))
	if _, err := conn.Write(probe); err != nil {
		return ""
	}

	// Read response from the active probe
	conn.SetReadDeadline(time.Now().Add(passiveTimeout))
	n, err = conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}

	return cleanBanner(string(buf[:n]))
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd synapse && go test ./internal/scanner -run TestGrabBannerActiveProbe`
Expected: PASS

- [ ] **Step 5: Run all tests to check regressions**

Run: `cd synapse && go test ./...`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
git add synapse/internal/scanner/scanner.go synapse/internal/scanner/scanner_test.go
git commit -m "feat(scanner): implement active http probe for banner grabbing"
```
