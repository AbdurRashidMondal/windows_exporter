# CLAUDE.md — Windows Exporter

This is a fork of [prometheus-community/windows_exporter](https://github.com/prometheus-community/windows_exporter), a Prometheus exporter for Windows metrics.

## Project Overview

- **Language:** Go 1.23+, Windows-only (`//go:build windows` required on all files)
- **License:** Apache 2.0 — all files must include the SPDX license header (enforced by linter)
- **Module:** `github.com/prometheus-community/windows_exporter`

## Directory Structure

```
cmd/windows_exporter/   # Main entry point
pkg/collector/          # Collector management & registration (central hub)
internal/
  collector/            # 45+ individual collector implementations
  pdh/                  # Performance Data Helper (Windows perf counters)
  mi/                   # WMI / Management Instrumentation
  config/               # YAML + CLI config parsing
  httphandler/          # /metrics, /health, /version endpoints
  log/                  # slog-based structured logging
  utils/                # Shared utilities
docs/                   # Per-collector documentation
installer/              # WiX MSI installer
```

## Key Conventions

### Every file must start with:
```go
// SPDX-License-Identifier: Apache-2.0
//
// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// ...

//go:build windows
```

### Collector structure (each under `internal/collector/<name>/`):
```go
const Name = "example"

type Config struct{}
var ConfigDefaults = Config{}

type Collector struct { /* PDH handles, metric descriptors */ }

func New(config *Config) *Collector
func NewWithFlags(app *kingpin.Application) *Collector
func (c *Collector) GetName() string
func (c *Collector) Build(logger *slog.Logger, miSession *mi.Session) error
func (c *Collector) Collect(ch chan<- prometheus.Metric) error
func (c *Collector) Close() error
```

### Collector registration (`pkg/collector/map.go`):
```go
var BuildersWithFlags = map[string]BuilderWithFlags[Collector]{
    example.Name: NewBuilderWithFlags(example.NewWithFlags),
}
```

### Default collectors:
```go
const DefaultCollectors = "cpu,memory,logical_disk,physical_disk,net,os,service,system,ginprocess,ginwebapp"
```

Custom collectors added to this project: **ginprocess** and **ginwebapp** (live in `pkg/collector/`, not `internal/collector/`).

## Linter Rules (golangci-lint)

- Do **not** use `syscall.*` — use `golang.org/x/sys/windows` instead
- Do **not** use `fmt.Print*` — use structured logging (`slog`)
- Do **not** use `windows.NewLazyDLL` — use the internal wrapper
- Run: `make lint`

## Build & Test Commands

```bash
make build       # Build windows_exporter.exe (also runs go generate)
make generate    # go generate ./...
make test        # go test -v ./...
make lint        # golangci-lint
make bench       # Benchmark collectors
make e2e-test    # PowerShell end-to-end tests
make crossbuild  # Build amd64 + arm64
make package     # Generate MSI installer
```

## Custom Additions (this fork)

- **`pkg/collector/ginprocess.go`** — Per-process CPU% and memory metrics
- **`pkg/collector/ginwebapp.go`** — ASP.NET/Gin web app metrics (requests/sec, errors, GC)
- Both are registered in `BuildersWithFlags` and included in `DefaultCollectors`

## Dependencies (key)

- `prometheus/client_golang` — Metrics library
- `alecthomas/kingpin/v2` — CLI flags
- `go-ole/go-ole` — COM/OLE (WMI)
- `shirou/gopsutil/v3` — System info
- `golang.org/x/sys` — Windows API

## Windows Requirements

- Windows Server 2016+ or Windows 10 21H2+
- Not compatible with Server 2012 R2 or earlier
