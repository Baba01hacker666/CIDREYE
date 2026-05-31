package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSendSummaryToTelegram(t *testing.T) {
	// Setup mock HTTP server
	var requestedPaths []string
	var requestBodies []string
	var contentType []string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPaths = append(requestedPaths, r.URL.Path)
		contentType = append(contentType, r.Header.Get("Content-Type"))

		body, _ := io.ReadAll(r.Body)
		requestBodies = append(requestBodies, string(body))

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	// Override the base URL for testing
	oldBaseURL := telegramAPIBaseURL
	telegramAPIBaseURL = ts.URL
	defer func() { telegramAPIBaseURL = oldBaseURL }()

	// Test case 1: Missing credentials
	t.Run("MissingCredentials", func(t *testing.T) {
		cfg := TelegramConfig{}
		err := sendSummaryToTelegram(cfg, []NucleiFinding{}, "")
		if err == nil {
			t.Errorf("expected error when bot token/chat id is missing")
		}
	})

	// Test case 2: Successful send with no findings (only summary)
	t.Run("SuccessNoFindings", func(t *testing.T) {
		requestedPaths = nil
		requestBodies = nil
		contentType = nil

		cfg := TelegramConfig{
			BotToken:      "test-token",
			ChatID:        "12345",
			UploadTimeout: 1 * time.Second,
		}

		err := sendSummaryToTelegram(cfg, []NucleiFinding{}, "")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if len(requestedPaths) != 1 {
			t.Fatalf("expected 1 request, got %d", len(requestedPaths))
		}
		if requestedPaths[0] != "/bot"+cfg.BotToken+"/sendMessage" {
			t.Errorf("expected path /bot%s/sendMessage, got %s", cfg.BotToken, requestedPaths[0])
		}
		if !strings.Contains(requestBodies[0], "chat_id=12345") {
			t.Errorf("expected body to contain chat_id, got %s", requestBodies[0])
		}
	})

	// Test case 3: Successful send with findings (summary + document)
	t.Run("SuccessWithFindings", func(t *testing.T) {
		requestedPaths = nil
		requestBodies = nil
		contentType = nil

		cfg := TelegramConfig{
			BotToken:      "test-token",
			ChatID:        "12345",
			UploadTimeout: 1 * time.Second,
		}

		findings := []NucleiFinding{
			{
				TemplateID: "test-vuln-1",
				Host:       "example.com",
				Info: struct {
					Name     string `json:"name"`
					Severity string `json:"severity"`
				}{
					Name:     "Test Vuln 1",
					Severity: "high",
				},
			},
		}

		// Create a temporary file to act as the raw results file
		tmpFile, err := os.CreateTemp("", "nuclei-test-results-*.jsonl")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		defer os.Remove(tmpFile.Name())

		// Write dummy data to it
		dummyData, _ := json.Marshal(findings[0])
		if _, err := tmpFile.Write(dummyData); err != nil {
			t.Fatalf("failed to write to temp file: %v", err)
		}
		tmpFile.Close()

		err = sendSummaryToTelegram(cfg, findings, tmpFile.Name())
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if len(requestedPaths) != 2 {
			t.Fatalf("expected 2 requests (summary + document), got %d", len(requestedPaths))
		}

		// First request should be sendMessage
		if requestedPaths[0] != "/bot"+cfg.BotToken+"/sendMessage" {
			t.Errorf("expected path /bot%s/sendMessage, got %s", cfg.BotToken, requestedPaths[0])
		}

		// Second request should be sendDocument
		if requestedPaths[1] != "/bot"+cfg.BotToken+"/sendDocument" {
			t.Errorf("expected path /bot%s/sendDocument, got %s", cfg.BotToken, requestedPaths[1])
		}
		if !strings.Contains(contentType[1], "multipart/form-data") {
			t.Errorf("expected multipart/form-data content type for document upload, got %s", contentType[1])
		}
	})

	// Test case 4: Server error handling
	t.Run("ServerError", func(t *testing.T) {
		errTs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"ok":false,"description":"Internal Server Error"}`))
		}))
		defer errTs.Close()

		oldBaseURL := telegramAPIBaseURL
		telegramAPIBaseURL = errTs.URL
		defer func() { telegramAPIBaseURL = oldBaseURL }()

		cfg := TelegramConfig{
			BotToken: "test-token",
			ChatID:   "12345",
		}

		// Because sendSummaryToTelegram doesn't check the response code for sendMessage,
		// we test sendToTelegram (which it calls when findings exist) because that does check status code
		findings := []NucleiFinding{{}}

		tmpFile, _ := os.CreateTemp("", "nuclei-test-results-*.jsonl")
		defer os.Remove(tmpFile.Name())
		tmpFile.Close()

		err := sendSummaryToTelegram(cfg, findings, tmpFile.Name())
		if err == nil {
			t.Errorf("expected error on server error")
		} else if !strings.Contains(err.Error(), "500") {
			t.Errorf("expected error to mention status 500, got %v", err)
		}
	})
}
