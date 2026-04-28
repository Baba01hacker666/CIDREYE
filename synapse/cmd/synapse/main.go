package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"synapse/internal/output"
	"synapse/internal/ports"
	"synapse/internal/scanner"
	"synapse/internal/targets"
)

type Config struct {
	Target      string `yaml:"target"`
	Ports       string `yaml:"ports"`
	Concurrency int    `yaml:"concurrency"`
	RateLimit   int    `yaml:"rate_limit"`
	TimeoutMs   int    `yaml:"timeout_ms"`
	Output      string `yaml:"output"`
	JSON        bool   `yaml:"json"`
	Quiet       bool   `yaml:"quiet"`
	Banner      bool   `yaml:"banner"`
}

func main() {
	var (
		configFile string
		targetFlag string
		portsFlag  string
		concFlag   int
		rateFlag   int
		timeFlag   int
		outFlag    string
		jsonFlag   bool
		quietFlag  bool
		bannerFlag bool
	)

	flag.StringVar(&configFile, "config", "", "Path to YAML config file")
	flag.StringVar(&targetFlag, "t", "", "Target IP, CIDR, or file (alias for --target)")
	flag.StringVar(&targetFlag, "target", "", "Target IP, CIDR, or file")
	flag.StringVar(&portsFlag, "p", "", "Ports to scan e.g., 80,443,1-1000 (alias for --ports)")
	flag.StringVar(&portsFlag, "ports", "", "Ports to scan e.g., 80,443,1-1000")
	flag.IntVar(&concFlag, "c", 1000, "Concurrency level (alias for --concurrency)")
	flag.IntVar(&concFlag, "concurrency", 1000, "Concurrency level")
	flag.IntVar(&rateFlag, "r", 0, "Rate limit in connections/sec (0 = unlimited) (alias for --rate)")
	flag.IntVar(&rateFlag, "rate", 0, "Rate limit in connections/sec (0 = unlimited)")
	flag.IntVar(&timeFlag, "timeout", 1000, "Timeout in milliseconds")
	flag.StringVar(&outFlag, "o", "", "Output file (alias for --output)")
	flag.StringVar(&outFlag, "output", "", "Output file")
	flag.BoolVar(&jsonFlag, "json", false, "Output in JSON format")
	flag.BoolVar(&quietFlag, "quiet", false, "Quiet mode (only print results)")
	flag.BoolVar(&bannerFlag, "banner", false, "Enable banner grabbing")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "SYNapse - High-performance userland TCP scanner\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	// Default config
	cfg := Config{
		Concurrency: concFlag,
		RateLimit:   rateFlag,
		TimeoutMs:   timeFlag,
		JSON:        jsonFlag,
		Quiet:       quietFlag,
		Banner:      bannerFlag,
	}

	// Load from YAML if provided
	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading config file: %v\n", err)
			os.Exit(1)
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing config file: %v\n", err)
			os.Exit(1)
		}
	}

	// Override with CLI flags if provided (CLI takes precedence over config file for strings/bools usually,
	// but here we just take whichever is not empty if flag was passed, for simplicity we overwrite if CLI flag is not default or empty)
	if targetFlag != "" {
		cfg.Target = targetFlag
	}
	if portsFlag != "" {
		cfg.Ports = portsFlag
	}
	if outFlag != "" {
		cfg.Output = outFlag
	}

	// Check required fields
	if cfg.Target == "" {
		fmt.Fprintln(os.Stderr, "Error: Target is required (-t, --target, or config file)")
		flag.Usage()
		os.Exit(1)
	}

	if cfg.Ports == "" {
		fmt.Fprintln(os.Stderr, "Error: Ports are required (-p, --ports, or config file)")
		flag.Usage()
		os.Exit(1)
	}

	// Setup Output Writer
	writer, err := output.NewWriter(cfg.Output, cfg.JSON, cfg.Quiet)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error setting up output: %v\n", err)
		os.Exit(1)
	}
	defer writer.Close()

	if !cfg.Quiet {
		writer.Log("SYNapse Scanner starting...")
		writer.Log("Target: %s", cfg.Target)
		writer.Log("Ports: %s", cfg.Ports)
		writer.Log("Concurrency: %d", cfg.Concurrency)
	}

	// Parse Ports
	parsedPorts, err := ports.Parse(cfg.Ports)
	if err != nil {
		writer.Log("Error parsing ports: %v", err)
		os.Exit(1)
	}

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		writer.Log("\nInterrupt received, shutting down...")
		cancel()
	}()

	// Setup Target Generator
	targetGen := targets.NewGenerator(cfg.Target)
	ipsCh, errCh := targetGen.Generate(ctx)

	go func() {
		for err := range errCh {
			if err != nil {
				writer.Log("Target generation error: %v", err)
			}
		}
	}()

	// Configure and Run Scanner
	scanCfg := scanner.Config{
		Concurrency: cfg.Concurrency,
		RateLimit:   cfg.RateLimit,
		Timeout:     time.Duration(cfg.TimeoutMs) * time.Millisecond,
		Banner:      cfg.Banner,
	}

	sc := scanner.New(scanCfg, writer)

	startTime := time.Now()
	if err := sc.Run(ctx, ipsCh, parsedPorts); err != nil {
		writer.Log("Scanner error: %v", err)
	}

	if !cfg.Quiet {
		writer.Log("Scan completed in %v", time.Since(startTime))
	}
}
