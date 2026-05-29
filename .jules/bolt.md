## Performance Optimizations

* **String Concatenation in Loops**: When repeatedly appending to a string inside a loop (e.g., building a summary report or logging output), avoid using the `+=` operator. This causes Go to allocate a new underlying byte slice on every iteration. Instead, declare a `var sb strings.Builder` and use `sb.WriteString(str)` for static strings or `fmt.Fprintf(&sb, format, args...)` for formatted strings. Finally, call `sb.String()` to retrieve the result. In benchmark tests within `nuclei_pipeline.go`, this reduced allocations per operation from 68 to 48 and improved execution time from ~6820 ns/op to ~4959 ns/op (a ~27% improvement).
### SYNapse Codebase

- **Buffered File I/O (May 2024)**: When repeatedly writing data to files in loops (e.g., generating nuclei target files), wrap the `*os.File` in a `bufio.NewWriter`. This prevents continuous system calls for unbuffered I/O and significantly improves write performance.
  - *Context:* `synapse/cmd/synapse/nuclei_pipeline.go`
  - *Impact:* Benchmark write times reduced from ~19ms/op to ~0.8ms/op (~22x improvement).
  - *Details:* Replaced `targetsFile.WriteString` inside a loop with `bufWriter := bufio.NewWriter(targetsFile)` and `bufWriter.Flush()` after the loop.
Go performance learning in SYNapse: When creating slices whose final size is known upfront (such as when iterating over a map or array), pre-allocate the slice capacity using `make([]Type, 0, knownLength)` rather than declaring an empty slice `var name []Type` to minimize memory reallocations during `append`.
