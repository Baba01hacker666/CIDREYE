# Performance Learnings in SYNapse

- **Go/I/O Buffering**: When repeatedly writing to files (e.g., inside loops), always wrap the file in a `bufio.NewWriter` to buffer writes and avoid the performance penalty of unbuffered filesystem interactions, ensuring you call `Flush()` when complete.
- **Go/Lock Contention**: To reduce lock contention in concurrent writers (e.g., the output writer), move CPU-intensive serialization logic (like `json.Marshal`, `fmt.Sprintf`) outside of mutex critical sections, exclusively locking around the actual I/O write operations.
- **Go/Network Loop Optimization**: Prefer using `net.Dialer.Timeout` over `context.WithTimeout` in high-frequency network loops (like TCP scanning) to avoid expensive background timer allocations. For fast IP/port string formatting, use `net.JoinHostPort` instead of `fmt.Sprintf`.
- **Python/Import Optimization**: Move optional third-party imports to the module level within `try...except ImportError` blocks and use a boolean availability flag to avoid the overhead of repeated import checks in function loops.
- **Python/Concurrent I/O Loop Optimization**: Use `concurrent.futures.ThreadPoolExecutor` to parallelize sequential blocking network I/O loops (e.g., iterative connection attempts). Iterate results with `concurrent.futures.as_completed(futures)` to return early upon success. This changes a loop from $O(N \times \text{timeout})$ to $O(1 \times \text{timeout})$.
## Performance Optimizations

### SYNapse Codebase

- **Buffered File I/O (May 2024)**: When repeatedly writing data to files in loops (e.g., generating nuclei target files), wrap the `*os.File` in a `bufio.NewWriter`. This prevents continuous system calls for unbuffered I/O and significantly improves write performance.
  - *Context:* `synapse/cmd/synapse/nuclei_pipeline.go`
  - *Impact:* Benchmark write times reduced from ~19ms/op to ~0.8ms/op (~22x improvement).
  - *Details:* Replaced `targetsFile.WriteString` inside a loop with `bufWriter := bufio.NewWriter(targetsFile)` and `bufWriter.Flush()` after the loop.
