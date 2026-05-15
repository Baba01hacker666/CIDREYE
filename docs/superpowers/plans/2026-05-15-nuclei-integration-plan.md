# Nuclei Integration Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve the Nuclei integration in `synapse` by adding template configuration, parsing JSONL output, and generating Telegram summary alerts.

**Architecture:** We will modify the existing `nuclei_pipeline.go` to invoke `nuclei` with `-jsonl`. A new Go struct `NucleiFinding` will be introduced to parse the output and programmatically filter by severity. The Telegram alerting function will be refactored to send a summary message, attaching the raw JSONL/txt file only if necessary. Configuration changes will be handled in `main.go`.

**Tech Stack:** Go (Standard Library), Nuclei CLI

---

### Task 1: Update Configuration Structs and CLI Flags

**Files:**
- Modify: `synapse/cmd/synapse/main.go`

- [ ] **Step 1: Write the failing test**
(Skipped for `main.go` CLI setup as it's tightly coupled to the `flag` package, but we will ensure the struct is updated)

- [ ] **Step 2: Update `Config` and `NucleiConfig` structs**
Modify `NucleiConfig` in `synapse/cmd/synapse/main.go` to include `Templates`:
```go
type NucleiConfig struct {
	Enabled     bool           `yaml:"enabled"`
	Tags        string         `yaml:"tags"`
	Templates   string         `yaml:"templates"`
	MinSeverity string         `yaml:"min_severity"`
	OutputFile  string         `yaml:"output_file"`
	Telegram    TelegramConfig `yaml:"telegram"`
}
```

- [ ] **Step 3: Add the CLI flag**
In `main.go`, add a `nucleiTemplates` variable and bind it to `--nuclei-templates`:
```go
var nucleiTemplates string
flag.StringVar(&nucleiTemplates, "nuclei-templates", "", "Comma-separated nuclei templates or directories")

// Later in the config override section:
if nucleiTemplates != "" {
    cfg.Nuclei.Templates = nucleiTemplates
}
```

- [ ] **Step 4: Commit**
```bash
git add synapse/cmd/synapse/main.go
git commit -m "feat(nuclei): add templates configuration support"
```

### Task 2: Define Nuclei JSON Structs and Helper Functions

**Files:**
- Create: `synapse/cmd/synapse/nuclei_pipeline_test.go`
- Modify: `synapse/cmd/synapse/nuclei_pipeline.go`

- [ ] **Step 1: Write the failing test**
Create `synapse/cmd/synapse/nuclei_pipeline_test.go`:
```go
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
```

- [ ] **Step 2: Run test to verify it fails**
Run: `cd synapse/cmd/synapse && go test -run TestParseSeverity`
Expected: FAIL with "parseSeverity not defined"

- [ ] **Step 3: Write minimal implementation**
In `synapse/cmd/synapse/nuclei_pipeline.go`, add the struct and `parseSeverity`:
```go
type NucleiFinding struct {
	TemplateID string `json:"template-id"`
	Host       string `json:"host"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"info"`
}

func parseSeverity(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "info":
		return 0
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	default:
		return -1
	}
}
```

- [ ] **Step 4: Run test to verify it passes**
Run: `cd synapse/cmd/synapse && go test -run TestParseSeverity`
Expected: PASS

- [ ] **Step 5: Commit**
```bash
git add synapse/cmd/synapse/nuclei_pipeline.go synapse/cmd/synapse/nuclei_pipeline_test.go
git commit -m "feat(nuclei): add json structs and severity parser"
```

### Task 3: Refactor Execution to use JSONL and Templates

**Files:**
- Modify: `synapse/cmd/synapse/nuclei_pipeline.go`

- [ ] **Step 1: Update execution arguments**
In `RunNucleiPipeline`, update the `args` construction to use `-jsonl` and the new `-t` flag if templates are provided:

```go
	outputFile := cfg.OutputFile
	if outputFile == "" {
		outputFile = "nuclei-results.jsonl"
	}

	args := []string{"-l", targetsFile.Name(), "-jsonl", "-o", outputFile, "-nc"}
	if cfg.Tags != "" {
		args = append(args, "-tags", cfg.Tags)
	}
	if cfg.Templates != "" {
		args = append(args, "-t", cfg.Templates)
	} else {
		args = append(args, "-as")
	}
```

- [ ] **Step 2: Replace `filterCriticalHigh` with programmatic parsing**
Remove the old `filterCriticalHigh` function and replace it with `filterBySeverity`:

```go
import "encoding/json"

func filterBySeverity(inputFile string, minSevStr string) ([]NucleiFinding, error) {
	file, err := os.Open(inputFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	minSev := parseSeverity(minSevStr)
	if minSev == -1 {
		minSev = 3 // default high
	}

	var findings []NucleiFinding
	decoder := json.NewDecoder(file)
	for decoder.More() {
		var finding NucleiFinding
		if err := decoder.Decode(&finding); err != nil {
			continue // skip invalid lines
		}
		if parseSeverity(finding.Info.Severity) >= minSev {
			findings = append(findings, finding)
		}
	}
	return findings, nil
}
```

- [ ] **Step 3: Commit**
```bash
git add synapse/cmd/synapse/nuclei_pipeline.go
git commit -m "feat(nuclei): run with jsonl and parse findings programmatically"
```

### Task 4: Enhance Telegram Alerting

**Files:**
- Modify: `synapse/cmd/synapse/nuclei_pipeline.go`

- [ ] **Step 1: Implement `sendSummaryToTelegram`**
Create a new function that accepts the parsed findings and sends a text summary, falling back to a document upload if needed.

```go
func sendSummaryToTelegram(cfg TelegramConfig, findings []NucleiFinding, rawFilePath string) error {
	if cfg.BotToken == "" || cfg.ChatID == "" {
		return fmt.Errorf("telegram enabled but bot token/chat id is missing")
	}

	severityCounts := make(map[string]int)
	for _, f := range findings {
		sev := strings.ToUpper(f.Info.Severity)
		severityCounts[sev]++
	}

	summary := "SYNapse Nuclei Scan Complete.\n"
	for sev, count := range severityCounts {
		summary += fmt.Sprintf("- %s: %d\n", sev, count)
	}
	
	summary += "\nTop Findings:\n"
	for i, f := range findings {
		if i >= 10 {
			summary += "... and more.\n"
			break
		}
		summary += fmt.Sprintf("[%s] %s on %s\n", strings.ToUpper(f.Info.Severity), f.TemplateID, f.Host)
	}

	// First try to send the text message
	timeout := cfg.UploadTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", cfg.BotToken)
	data := strings.NewReader(fmt.Sprintf("chat_id=%s&text=%s", cfg.ChatID, strings.ReplaceAll(summary, "\n", "%0A")))
	req, _ := http.NewRequest(http.MethodPost, url, data)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()

	// If there are many findings, also send the document
	if len(findings) > 0 {
		return sendToTelegram(cfg, rawFilePath)
	}
	return nil
}
```

- [ ] **Step 2: Wire it into `RunNucleiPipeline`**
Replace the Telegram block in `RunNucleiPipeline`:

```go
	if cfg.Telegram.Enabled {
		findings, err := filterBySeverity(outputFile, minSeverity)
		if err != nil {
			return fmt.Errorf("filter telegram output: %w", err)
		}

		if len(findings) == 0 {
			writer.Log("No findings met the severity threshold for Telegram. Skipping.")
			return nil
		}

		if err := sendSummaryToTelegram(cfg.Telegram, findings, outputFile); err != nil {
			return fmt.Errorf("telegram send failed: %w", err)
		}
		writer.Log("Nuclei output sent to Telegram chat %s", cfg.Telegram.ChatID)
	}
```

- [ ] **Step 3: Run the build to ensure compilation succeeds**
Run: `cd synapse && go build ./cmd/synapse`
Expected: Successful compilation without errors.

- [ ] **Step 4: Commit**
```bash
git add synapse/cmd/synapse/nuclei_pipeline.go
git commit -m "feat(nuclei): generate formatted telegram summaries"
```
