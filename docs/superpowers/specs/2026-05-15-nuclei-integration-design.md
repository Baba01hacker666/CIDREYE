# Nuclei Integration Improvements Design

## 1. Overview
The goal is to improve the `synapse` wrapper for Nuclei. The current implementation executes the `nuclei` binary with plain text output, relies on string matching for severity filtering, and uploads a raw `.txt` file to Telegram. This design transitions the pipeline to use structured JSONL output, adds configuration flexibility, and significantly enhances the Telegram alerting experience.

## 2. Configuration & Command Line
- **New Field:** Add `Templates` (string or slice of strings) to `NucleiConfig` in `config.yaml` and a new CLI flag `--nuclei-templates` (comma-separated).
- **Execution Logic:** If `Templates` are provided, the `-t` argument will be passed to `nuclei` instead of `-as` (automatic technology detection). `-as` will be used as a fallback if no templates are specified.
- **Existing Fields:** Keep `Tags` and `MinSeverity`.

## 3. Output & Parsing
- **JSONL Mode:** The `exec.Command` will invoke `nuclei` with the `-jsonl` flag (or `-je` to directly output JSON).
- **Go Structs:** Introduce a `NucleiFinding` struct in Go to parse the JSON output (fields: `info.name`, `info.severity`, `template-id`, `host`, `matched-at`, `extracted-results`).
- **In-Memory Filtering:** Unmarshal each line, and apply the `min_severity` filter programmatically using a numeric severity mapping rather than basic string `strings.Contains`.
- **Output Storage:** Save the parsed and filtered results to `output_file` (either as pretty text or JSONL, depending on the configured file extension).

## 4. Telegram Alerting
- **Message Summary:** Instead of only uploading a file, generate a formatted summary message for the chat body. 
  - Example: `SYNapse Nuclei Scan Complete. 🔴 CRITICAL: 2, 🟠 HIGH: 5`
  - Group findings by target or severity and list the top findings (e.g., `<severity> <template-id> on <host>`).
- **File Upload Fallback:** If the summary exceeds Telegram's 4096 character message limit (or if there are many findings), send the short summary in the message body and attach the detailed findings as a formatted text or JSONL document.

## 5. Error Handling
- Capture Nuclei `stderr` to log if it fails to start or encounters internal errors.
- Handle JSON unmarshaling errors gracefully without crashing the pipeline (log and skip the line).
- Ensure temporary files are correctly cleaned up (`defer os.Remove`) even in error scenarios.
