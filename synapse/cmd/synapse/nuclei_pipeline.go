package main

import (
	"encoding/json"
	"bufio"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"synapse/internal/output"
)

type NucleiConfig struct {
	Enabled     bool           `yaml:"enabled"`
	Tags        string         `yaml:"tags"`
	Templates   string         `yaml:"templates"`
	MinSeverity string         `yaml:"min_severity"`
	OutputFile  string         `yaml:"output_file"`
	Telegram    TelegramConfig `yaml:"telegram"`
}

type TelegramConfig struct {
	Enabled       bool          `yaml:"enabled"`
	BotToken      string        `yaml:"bot_token"`
	ChatID        string        `yaml:"chat_id"`
	UploadTimeout time.Duration `yaml:"upload_timeout"`
}

func RunNucleiPipeline(writer *output.Writer, openTargets []string, cfg NucleiConfig) error {
	if len(openTargets) == 0 {
		writer.Log("Nuclei pipeline enabled, but no open ports found. Skipping.")
		return nil
	}

	targetsFile, err := os.CreateTemp("", "synapse-open-targets-*.txt")
	if err != nil {
		return fmt.Errorf("create nuclei targets file: %w", err)
	}
	defer os.Remove(targetsFile.Name())
	defer targetsFile.Close()

	for _, t := range openTargets {
		if _, err := targetsFile.WriteString(t + "\n"); err != nil {
			return fmt.Errorf("write nuclei targets: %w", err)
		}
	targetsFile.Close()
	}

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

	writer.Log("Running nuclei...")
	cmd := exec.Command("nuclei", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run nuclei: %w", err)
	}

	if cfg.Telegram.Enabled {
		findings, err := filterBySeverity(outputFile, cfg.MinSeverity)
		if err != nil {
			return fmt.Errorf("filter telegram output: %w", err)
		}

		if len(findings) == 0 {
			writer.Log("No findings matching minimum severity to send to Telegram. Skipping upload.")
			return nil
		}

		filteredFile, err := os.CreateTemp("", "synapse-telegram-*.json")
		if err != nil {
			return fmt.Errorf("create telegram output file: %w", err)
		}
		defer os.Remove(filteredFile.Name())

		encoder := json.NewEncoder(filteredFile)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(findings); err != nil {
			filteredFile.Close()
			return fmt.Errorf("encode telegram output: %w", err)
		}
		filteredFile.Close()

		if err := sendToTelegram(cfg.Telegram, filteredFile.Name()); err != nil {
			return fmt.Errorf("telegram send failed: %w", err)
		}
		writer.Log("Nuclei output sent to Telegram chat %s", cfg.Telegram.ChatID)
	}
	return nil
}

func sendToTelegram(cfg TelegramConfig, filePath string) error {
	if cfg.BotToken == "" || cfg.ChatID == "" {
		return fmt.Errorf("telegram enabled but bot token/chat id is missing")
	}
	timeout := cfg.UploadTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	bodyReader, bodyWriter := io.Pipe()
	mw := multipart.NewWriter(bodyWriter)

	go func() {
		defer bodyWriter.Close()
		defer mw.Close()
		_ = mw.WriteField("chat_id", cfg.ChatID)
		part, err := mw.CreateFormFile("document", filePath)
		if err != nil {
			_ = bodyWriter.CloseWithError(err)
			return
		}
		if _, err := io.Copy(part, file); err != nil {
			_ = bodyWriter.CloseWithError(err)
		}
	}()

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", cfg.BotToken)
	req, err := http.NewRequest(http.MethodPost, url, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("telegram API returned status %s", resp.Status)
	}
	return nil
}

func filterBySeverity(inputFile string, minSevStr string) ([]NucleiFinding, error) {
	file, err := os.Open(inputFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []NucleiFinding{}, nil
		}
		return nil, err
	}
	defer file.Close()

	minSev := parseSeverity(minSevStr)
	if minSev == -1 {
		minSev = 3 // default high
	}

	var findings []NucleiFinding
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var finding NucleiFinding
		if err := json.Unmarshal(line, &finding); err != nil {
			continue // skip invalid lines
		}
		if parseSeverity(finding.Info.Severity) >= minSev {
			findings = append(findings, finding)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return findings, nil
}

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

