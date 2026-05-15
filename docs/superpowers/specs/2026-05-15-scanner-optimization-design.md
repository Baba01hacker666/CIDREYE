# Synapse Scanner Optimizations Design

## 1. Overview
The goal is to improve the core capabilities and stability of the `synapse` Go scanner. Currently, high concurrency scans can crash or fail to connect due to OS-level file descriptor limits (`ulimit`). Furthermore, the passive banner grabber misses many modern services (like HTTP servers) that wait for the client to send data first. This design addresses both issues natively within the Go binary.

## 2. Automatic File Descriptor Limits (ulimit)
- **Concept:** By default, Linux/macOS systems limit a process to 1024 open file descriptors. A scanner with 5,000 concurrency will quickly exhaust this and throw `socket: too many open files` errors.
- **Implementation:** 
  - Create a new package/utility file `internal/sysutil/fd_limit.go`.
  - Use `syscall.Getrlimit` and `syscall.Setrlimit` (conditionally compiled for Unix systems using `//go:build !windows`) to raise `RLIMIT_NOFILE` to the maximum allowable hard limit at startup.
  - Call this function at the very beginning of `main.go`. If it fails (due to permissions), log a warning but allow the scan to proceed.

## 3. Active Protocol Probes (Banner Grabbing)
- **Concept:** Enhance the existing `grabBanner` function in `internal/scanner/scanner.go`.
- **Implementation:**
  - **Phase 1 (Passive):** Set a short read deadline (e.g., 1-2 seconds) and attempt to read from the connection. This captures banners from "server-speaks-first" protocols like SSH, FTP, and SMTP.
  - **Phase 2 (Active):** If Phase 1 times out or returns 0 bytes, write a generic active probe to the connection: `GET / HTTP/1.0\r\n\r\n`.
  - Set a new short read deadline and attempt to read again. This will coax a response out of HTTP/HTTPS servers and many custom TCP services.
  - Clean the resulting bytes (removing non-printable characters and newlines) before returning.
- **Benefits:** Massively increases the visibility of web services directly within the Go binary output without relying on external Python modules.

## 4. Error Handling & Stability
- The `Setrlimit` call will safely degrade. Windows systems will use a no-op implementation.
- The banner grabber will handle read/write timeouts gracefully without extending the overall scan time significantly, as the active probe is only triggered if the passive read yields nothing.