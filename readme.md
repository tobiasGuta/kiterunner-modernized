# Kiterunner (Modernized)

![](/hack/kiterunner.png)

[![GoDoc](https://godoc.org/github.com/assetnote/kiterunner?status.svg)](https://godoc.org/github.com/assetnote/kiterunner)
[![GitHub release](https://img.shields.io/github/release/assetnote/kiterunner.svg)](https://github.com/assetnote/kiterunner/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/assetnote/kiterunner)](https://goreportcard.com/report/github.com/assetnote/kiterunner)

This is a modernized fork of the original [Assetnote Kiterunner](https://github.com/assetnote/kiterunner).

Kiterunner is a high-performance content discovery tool designed for identifying API endpoints and routes in modern web applications. While traditional tools focus on files and folders, Kiterunner leverages datasets of API specifications (Swagger/OpenAPI) to brutally effectuate endpoint discovery with correct HTTP methods, headers, and parameters.

## Modernization Improvements

This fork introduces significant enhancements to the original engine:

*   **Next-Gen Engine:** Ported to Go 1.25+ for improved concurrency and memory management.
*   **WAF Evasion & Stealth:** Implemented Request Jitter, Smart Adaptive Backoff (Retry-After/Exponential), and optional Proxy Rotation.
*   **Intelligence:** Enhanced Smart 404 Calibration to reduce false positives in complex API environments.
*   **Workflow Integration:** Native support for replaying valid findings to a downstream proxy (e.g., Burp Suite) for automated workflow integration.
*   **Hot-Loading:** Ability to consume remote Swagger specifications directly as wordlists.

## Installation

### From Source

Ensure you have Go 1.25+ installed.

```bash
git clone https://github.com/assetnote/kiterunner
cd kiterunner
go install ./cmd/kiterunner
```

To make the ./kr command work as you typed it, you need to build it specifically to the current folder:

```bash
go build -o kr ./cmd/kiterunner
```

Or using Make:

```bash
make build
```

## Usage

### Quick Start

```bash
# Scan a target using a specific wordlist
kr scan https://target.com -w routes.kite

# Scan using Assetnote's hosted wordlists
kr scan https://target.com -A apiroutes-210228
```

### New Features & Flags

#### 1. Input Flexibility
Kiterunner now supports diverse input methods for modern pipelines.

*   **JSONL Support:** Pipe JSON lines containing `url` or `target` fields directly into the tool.
*   **Swagger Hot-Loading:** Directly pass a URL to a remote Swagger/OpenAPI file as a wordlist. The tool will parse and generate routes on the fly.

```bash
# Hot-load a remote swagger file
kr scan target.com -w https://target.com/api/v1/docs.json
```

#### 2. Stealth & Evasion
Mechanisms to bypass rate limits and WAFs.

| Flag | Description |
|------|-------------|
| `--jitter <int>` | Adds a random percentage variance (0-100) to the configured delay. |
| `--delay <duration>` | Base delay between requests (e.g., `500ms`). |
| `--proxy-list <file>` | Path to a file containing a list of proxies (one per line). Requests will be rotated round-robin. |

*Note: Smart Backoff is enabled automatically. If a 429 response is received, the tool respects the `Retry-After` header or applies exponential backoff.*

#### 3. Intelligence (Smart Calibration)
The `--calibrate` flag (enabled by default) performs dynamic analysis of the target's 404 behavior. It sends random probes to determine the structure of "Not Found" responses, drastically reducing false positives on APIs that return 200 OK for errors.

#### 4. Workflow Integration (Burp Suite)
Automatically populate your Proxy History with confirmed hits while keeping noise out.

| Flag | Description |
|------|-------------|
| `--replay-proxy <url>` | valid findings are asynchronously replayed to this upstream proxy (e.g., `http://127.0.0.1:8080`). |

## Bug Hunter's Cheat Sheet

### Pipeline Mode
Integrate with other tools using JSON input.

```bash
subfinder -d target.com | httpx -json | kr scan --json-input -w routes.kite
```

### Stealth Mode
Scan sensitive targets with randomized timing to avoid pattern detection.

```bash
kr scan target.com --jitter 20 --delay 200ms -w routes.kite
```

### WAF Evasion
Rotate IP addresses and feed results directly to Burp Suite for analysis.

```bash
kr scan target.com --proxy-list proxies.txt --replay-proxy http://127.0.0.1:8080 -A apiroutes-210228
```

### Hot-Loading
Quickly check if a disclosed Swagger file contains accessible endpoints without manually parsing it.

```bash
kr scan target.com -w https://target.com/docs.json
```

###  Handling 415 Errors
Modern APIs often reject requests that lack a content type, even if the route exists. If you see many `415` errors, verify your headers:

```bash
# Force JSON content type to bypass 415 errors
./kr scan target.com -w routes.kite -H "Content-Type: application/json"
```
