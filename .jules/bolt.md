## Performance Optimizations

### SYNapse Codebase

- **Buffered File I/O (May 2024)**: When repeatedly writing data to files in loops (e.g., generating nuclei target files), wrap the `*os.File` in a `bufio.NewWriter`. This prevents continuous system calls for unbuffered I/O and significantly improves write performance.
  - *Context:* `synapse/cmd/synapse/nuclei_pipeline.go`
  - *Impact:* Benchmark write times reduced from ~19ms/op to ~0.8ms/op (~22x improvement).
  - *Details:* Replaced `targetsFile.WriteString` inside a loop with `bufWriter := bufio.NewWriter(targetsFile)` and `bufWriter.Flush()` after the loop.
