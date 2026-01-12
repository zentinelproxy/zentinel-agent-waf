# Sentinel WAF Agent

A next-generation Web Application Firewall agent for [Sentinel](https://github.com/raskell-io/sentinel) reverse proxy. Built in **pure Rust** with no C dependencies, featuring ML-powered detection, anomaly scoring, and enterprise-grade protection.

## Features

### Core Detection (200+ Rules)
- **SQL Injection** - UNION, blind, time-based, stacked queries, NoSQL
- **Cross-Site Scripting (XSS)** - Reflected, stored, DOM-based, polyglot
- **Path Traversal** - Directory traversal, LFI, RFI
- **Command Injection** - Shell, Windows cmd, expression languages
- **Server-Side Template Injection (SSTI)** - Jinja2, Twig, Freemarker
- **LDAP/XPath Injection**
- **SSRF Detection** - Internal IP ranges, cloud metadata endpoints
- **Insecure Deserialization**

### Advanced Protection
- **API Security** - GraphQL introspection blocking, JSON depth limits, JWT validation
- **Bot Detection** - Scanner fingerprints, behavioral analysis, timing anomalies
- **Credential Stuffing Protection** - Breach checking, velocity detection
- **Sensitive Data Detection** - Credit cards, SSN, API keys, PII masking
- **Supply Chain Protection** - SRI validation, crypto miner detection, Magecart patterns

### Enterprise Features
- **Threat Intelligence** - IP/domain reputation, IoC feeds, Tor exit node detection
- **Virtual Patching** - Built-in CVE signatures (Log4Shell, Spring4Shell, Shellshock)
- **Advanced Analytics** - Prometheus/OpenTelemetry metrics, latency histograms
- **Federated Learning** - Privacy-preserving distributed model training

### Performance
- **Anomaly Scoring** - Cumulative risk scores instead of binary block/allow
- **ML Classification** - Character n-gram based attack detection
- **Regex Automata** - DFA-based multi-pattern matching for O(n) scanning
- **Streaming Inspection** - Constant memory body inspection with sliding window
- **Plugin Architecture** - Extensible rule and detection system

## Installation

### From Source

```bash
git clone https://github.com/raskell-io/sentinel-agent-waf
cd sentinel-agent-waf
cargo build --release
```

### Binary

```bash
# After building
./target/release/sentinel-waf-agent --socket /var/run/sentinel/waf.sock
```

## Quick Start

```bash
# Basic usage with default settings
sentinel-waf-agent --socket /var/run/sentinel/waf.sock

# With higher sensitivity
sentinel-waf-agent --socket /var/run/sentinel/waf.sock --paranoia-level 2

# Detect-only mode (no blocking)
sentinel-waf-agent --socket /var/run/sentinel/waf.sock --block-mode false
```

## Configuration

### Command Line Options

| Option | Environment Variable | Description | Default |
|--------|---------------------|-------------|---------|
| `--socket` | `AGENT_SOCKET` | Unix socket path | `/tmp/sentinel-waf.sock` |
| `--paranoia-level` | `WAF_PARANOIA_LEVEL` | Sensitivity (1-4) | `1` |
| `--block-mode` | `WAF_BLOCK_MODE` | Block or detect-only | `true` |
| `--config` | `WAF_CONFIG` | JSON config file path | - |

### JSON Configuration

```json
{
  "paranoia-level": 2,
  "scoring": {
    "enabled": true,
    "block-threshold": 25,
    "log-threshold": 10
  },
  "rules": {
    "enabled": ["942*", "941*", "932*"],
    "disabled": ["942100"],
    "exclusions": [{
      "rules": ["942110"],
      "conditions": { "paths": ["/api/admin"] }
    }]
  },
  "api-security": {
    "graphql-enabled": true,
    "block-introspection": true,
    "jwt-block-none": true
  },
  "bot-detection": {
    "enabled": true,
    "timing-analysis": true
  },
  "sensitive-data": {
    "enabled": true,
    "mask-in-logs": true
  },
  "threat-intel": {
    "enabled": true,
    "block-tor-exit-nodes": true
  },
  "virtual-patching": {
    "enabled": true,
    "log-matches": true
  },
  "metrics": {
    "enabled": true,
    "per-rule-metrics": true
  }
}
```

## Paranoia Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| 1 | High-confidence detections only | Production (recommended) |
| 2 | Medium-confidence rules added | Production with tuning |
| 3 | Low-confidence rules added | Staging/testing |
| 4 | Maximum sensitivity | Security audits |

## Anomaly Scoring

Instead of binary block/allow, the WAF calculates cumulative risk scores:

```
Total Score = Σ(rule_score × severity_multiplier × location_weight)
```

| Score Range | Action |
|-------------|--------|
| 0-9 | Allow |
| 10-24 | Log (warning) |
| 25+ | Block |

### Severity Multipliers

| Severity | Multiplier |
|----------|------------|
| Critical | 2.0x |
| High | 1.5x |
| Medium | 1.0x |
| Low | 0.7x |
| Info | 0.3x |

### Location Weights

| Location | Weight |
|----------|--------|
| Query String | 1.5x |
| Cookie | 1.3x |
| Path | 1.2x |
| Body | 1.2x |
| Headers | 1.0x |

## Rule Categories

### SQL Injection (942xxx)
- 942100-942199: Basic patterns
- 942200-942299: Database functions
- 942300-942399: SQL keywords
- 942400-942499: Blind injection

### XSS (941xxx)
- 941100-941199: Script tags
- 941200-941299: Event handlers
- 941300-941399: JavaScript URIs
- 941400-941499: HTML injection

### Command Injection (932xxx)
- 932100-932149: Unix commands
- 932150-932199: Windows commands
- 932200-932299: Shell expressions

### Path Traversal (930xxx)
- 930100-930149: Basic traversal
- 930150-930199: OS file detection

### Protocol Attacks (920xxx)
- 920100-920199: Request anomalies
- 920200-920299: Protocol violations

### Scanner Detection (913xxx)
- 913100-913199: User-Agent patterns

### SSTI (934xxx)
- 934100-934199: Template injection

### Supply Chain (92xxx)
- 92000-92099: Script integrity
- 92100-92199: Malicious patterns
- 92200-92299: Obfuscation

### Virtual Patches (93xxx)
- 93700: Log4Shell (CVE-2021-44228)
- 93701: Spring4Shell (CVE-2022-22965)
- 93702: Shellshock (CVE-2014-6271)

### Threat Intelligence (94xxx)
- 94000-94099: IP reputation
- 94100-94199: Domain reputation
- 94200-94299: IoC matches

## API Security

### GraphQL Protection
- Introspection query blocking
- Query depth limiting
- Batch query detection

### JWT Validation
- "none" algorithm detection
- Weak algorithm warnings
- Expired token detection

### JSON Security
- Deep nesting detection
- Prototype pollution patterns
- NoSQL injection patterns

## Metrics

### Prometheus Format
```
GET /metrics

# HELP waf_requests_total Total requests processed
# TYPE waf_requests_total counter
waf_requests_total 12345

# HELP waf_requests_blocked Total requests blocked
# TYPE waf_requests_blocked counter
waf_requests_blocked 42

# HELP waf_inspection_latency_seconds Request inspection latency
# TYPE waf_inspection_latency_seconds histogram
waf_inspection_latency_seconds_bucket{le="0.001"} 10000
waf_inspection_latency_seconds_bucket{le="0.005"} 12000
```

### JSON Format
```json
GET /metrics?format=json

{
  "requests_total": 12345,
  "requests_blocked": 42,
  "detections_by_attack_type": {
    "SQL Injection": 15,
    "Cross-Site Scripting": 8
  }
}
```

## Sentinel Proxy Integration

```kdl
agents {
    agent "waf" {
        type "custom"
        transport "unix_socket" {
            path "/var/run/sentinel/waf.sock"
        }
        events ["request_headers", "request_body_chunk", "response_body_chunk"]
        timeout-ms 50
        failure-mode "open"
    }
}

routes {
    route "api" {
        matches { path-prefix "/api" }
        upstream "backend"
        agents ["waf"]
    }
}
```

## Response Headers

### On Blocked Requests
```
X-WAF-Blocked: true
X-WAF-Rule: 942100
X-WAF-Score: 35
X-WAF-Attack-Type: SQL Injection
```

### On Detected (Non-Blocking)
```
X-WAF-Detected: 942100,941100
X-WAF-Score: 15
```

## Performance Benchmarks

| Metric | Target | Actual |
|--------|--------|--------|
| Rule matching (1KB input) | <5ms | ~2ms |
| Memory per request | <1KB | ~500B |
| Throughput | >50K req/s | 65K req/s |
| Binary size | <10MB | ~6MB |

Run benchmarks:
```bash
cargo bench
```

## Testing

```bash
# Unit tests
cargo test --lib

# Integration tests
cargo test --test integration_tests

# CRS compatibility tests
cargo test --test crs_compatibility

# All tests
cargo test
```

## Development

```bash
# Debug build with logging
RUST_LOG=debug cargo run -- --socket /tmp/test.sock

# Release build
cargo build --release

# Check formatting
cargo fmt --check

# Lint
cargo clippy
```

## Comparison with ModSecurity

| Feature | sentinel-agent-waf | ModSecurity CRS |
|---------|-------------------|-----------------|
| Detection Rules | 200+ | 800+ |
| ML Detection | ✓ | ✗ |
| Anomaly Scoring | ✓ | ✓ |
| API Security | ✓ (GraphQL, JWT) | Basic |
| Bot Detection | ✓ (behavioral) | UA only |
| Threat Intel | ✓ | ✗ |
| Virtual Patching | ✓ | ✗ |
| Dependencies | Pure Rust | C library |
| Binary Size | ~6MB | ~50MB |
| Latency p99 | <5ms | ~15ms |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Sentinel Proxy                           │
└─────────────────────────┬───────────────────────────────────┘
                          │ Unix Socket
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                  WAF Agent                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  Automata   │  │     ML      │  │    Threat Intel     │  │
│  │   Engine    │  │  Classifier │  │      Engine         │  │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
│         │                │                     │            │
│         └────────────────┼─────────────────────┘            │
│                          ▼                                  │
│                 ┌─────────────────┐                         │
│                 │ Anomaly Scorer  │                         │
│                 └────────┬────────┘                         │
│                          ▼                                  │
│                 ┌─────────────────┐                         │
│                 │    Decision     │ → Block / Allow / Log   │
│                 └─────────────────┘                         │
└─────────────────────────────────────────────────────────────┘
```

## License

Apache-2.0

## Contributing

Contributions welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

Report security vulnerabilities to security@raskell.io.
