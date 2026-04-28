# SYNapse

A high-performance, non-root, userland TCP scanner built in pure Go. Inspired by masscan, it is designed for rapid and concurrent scanning utilizing only standard OS networking `net.Dial`, without needing raw sockets or `pcap`.

## Features
- **High Concurrency**: Goroutine-based bounded worker pool capable of thousands of concurrent connections.
- **No Root Required**: Built purely on standard TCP dialing, avoiding the need for elevated privileges or raw socket access.
- **Multiple Target Inputs**: Supports single IPs, CIDR ranges, and files containing lists of IPs/CIDRs.
- **Flexible Port Formats**: Single port (`80`), comma-separated lists (`80,443`), and ranges (`1-1000`).
- **Rate Limiting**: Configurable maximum connections per second.
- **Output Formats**: Standard plain text or JSON output, with optional file saving.
- **Optional Banner Grabbing**: Identifies basic banners (e.g., SSH, HTTP) from open ports.

## Installation

```bash
go build -o synapse ./cmd/synapse
```

## Usage

```bash
# Basic scan of a single IP
./synapse -t 192.168.1.1 -p 80,443

# Scan a CIDR range with custom concurrency and timeout
./synapse -t 10.0.0.0/24 -p 1-1000 -c 5000 --timeout 500

# Scan from a file containing targets, save as JSON, and enable banner grabbing
./synapse -t targets.txt -p 22,80 -o results.json --json --banner
```

### Configuration via YAML

You can also use a YAML configuration file to set defaults:

```yaml
target: "192.168.1.0/24"
ports: "80,443,8080"
concurrency: 2000
rate_limit: 5000
timeout_ms: 800
json: true
banner: true
```

Run with the config file:
```bash
./synapse -config config.yaml
```

CLI flags take precedence over the YAML configuration.

## Performance Target
SYNapse is tuned for minimal memory allocation and fast throughput. Depending on your system and network configuration, it can handle a massive number of concurrent connections (50k-200k+/sec). You may need to increase your OS file descriptor limits (`ulimit -n`) for optimal performance on large ranges.
