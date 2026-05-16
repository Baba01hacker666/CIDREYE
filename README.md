# CIDREYE

CIDREYE contains **SYNapse**, a high-performance non-root TCP scanner written in Go with an optional Python wrapper for post-scan service modules.

## Project layout

```text
.
├── Makefile                 # Root build/test/run entry points
├── go.work                  # Go workspace pointing at the nested SYNapse module
├── synapse/                 # Scanner source, wrapper, config, and tests
│   ├── cmd/synapse/         # Go CLI entry point
│   ├── internal/            # Go scanner packages
│   ├── py_modules/          # Optional Python enrichment modules
│   ├── config.yaml          # Wrapper defaults
│   ├── requirements.txt     # Python wrapper dependencies
│   └── synapse.py           # Python wrapper
└── docs/                    # Design notes and specifications
```

## Quick start

```bash
# Show the supported developer commands
make help

# Build the Go scanner to ./bin/synapse
make build

# Run all Go and Python tests
make test
```

Run the scanner directly:

```bash
make run ARGS="-t 127.0.0.1 -p 22,80 --timeout 250"
```

Run the Python wrapper, which auto-discovers the root `./bin/synapse` binary after `make build`:

```bash
make wrapper ARGS="--target 127.0.0.1 --ports 22,80"
```

## Dependencies

- Go 1.24+
- Python 3 with `pip`

Install dependencies with:

```bash
make deps
```

`make deps` downloads Go modules and installs Python packages from `synapse/requirements.txt`.

## Manual commands

If you do not want to use `make`, these are the equivalent core commands:

```bash
go build -trimpath -o bin/synapse ./synapse/cmd/synapse
go test ./synapse/...
cd synapse && python3 -m pytest -q
```

See [`synapse/README.md`](synapse/README.md) for scanner flags, YAML configuration, nuclei integration, and wrapper details.
