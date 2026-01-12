# Roadmap

## Current Status (v0.7.0)

The WAF agent has evolved into a **next-generation Web Application and API Protection (WAAP)** platform with ML-powered detection, anomaly scoring, and enterprise-grade features.

### What Works

**Core Detection (200+ Rules)**
- SQL injection (UNION, blind, time-based, stacked, NoSQL)
- Cross-site scripting (reflected, stored, DOM-based, polyglot)
- Path traversal and file inclusion (LFI/RFI)
- Command injection (Unix, Windows, expression languages)
- Server-side template injection (SSTI)
- LDAP/XPath injection
- SSRF detection
- Insecure deserialization

**Advanced Features**
- Anomaly scoring with configurable thresholds
- ML-based attack classification (character n-gram model)
- Request fingerprinting and behavioral analysis
- Payload similarity detection
- Streaming body inspection with sliding window
- Plugin architecture for extensibility
- regex-automata DFA-based multi-pattern matching

**API Security**
- GraphQL introspection blocking and depth limits
- JWT validation ("none" algorithm, weak algorithms, expiry)
- JSON depth/complexity limits
- NoSQL injection patterns

**Bot Detection**
- Scanner fingerprint detection
- Behavioral analysis and timing anomalies
- TLS fingerprinting support
- Good bot verification

**Enterprise Features**
- Credential stuffing protection with breach checking
- Sensitive data detection (credit cards, SSN, API keys)
- Supply chain attack detection (SRI, crypto miners, Magecart)
- Virtual patching (Log4Shell, Spring4Shell, Shellshock)
- Threat intelligence integration (IP/domain reputation, IoC feeds)
- Federated learning with differential privacy
- Prometheus/OpenTelemetry metrics

**Operational**
- Request and response body inspection
- WebSocket frame inspection (text/binary, fragmented messages)
- Paranoia levels 1-4
- Block mode and detect-only mode
- Path exclusions
- Graceful shutdown and health checks
- Production panic handling

### What Doesn't Work

- Body content modification (can only block/allow)
- OpenAPI/GraphQL schema validation (pattern-based only)
- Higher paranoia level rules (levels 2-4 have limited coverage)

---

## Completed Milestones

### v0.2.0 - Response Inspection ✓

**Status: Complete**

- [x] Implement `on_response_body_chunk()` handler
- [x] Add `--response-inspection` flag
- [x] Reuse existing detection rules for response bodies
- [x] Add tests for response body inspection

### v0.3.0 - Streaming Mode Support ✓

**Status: Complete**

- [x] Implement streaming body inspection with sliding window
- [x] Add `StreamingInspector` with overlap buffer for cross-chunk patterns
- [x] Early termination on high anomaly scores
- [x] Memory-efficient inspection (~1KB per request vs 1MB buffered)

### v0.4.0 - Integration Tests ✓

**Status: Complete**

- [x] Create integration test harness
- [x] Test SQL injection detection (29 test cases)
- [x] Test XSS detection
- [x] Test path traversal detection
- [x] Test command injection detection
- [x] Test bot detection
- [x] Test sensitive data detection
- [x] Test false positive scenarios
- [x] Add OWASP CRS compatibility tests (15 test cases)
- [x] Add performance benchmarks (Criterion)

### Next-Gen Phase 1: Foundation ✓

**Status: Complete**

- [x] Expand to 200+ high-quality detection rules
- [x] Implement regex-automata DFA-based matching
- [x] Add rule management (enable/disable, exclusions, overrides)
- [x] Create plugin architecture (`WafPlugin` trait)

### Next-Gen Phase 2: Intelligence ✓

**Status: Complete**

- [x] Anomaly scoring engine with severity/location weights
- [x] ML-based attack classification
- [x] Request fingerprinting and baseline learning
- [x] Payload embedding similarity detection

### Next-Gen Phase 3: Modern Threats ✓

**Status: Complete**

- [x] API security (GraphQL, JWT, JSON)
- [x] Bot detection (signatures, behavior, timing)
- [x] Credential stuffing protection
- [x] Sensitive data detection
- [x] Supply chain attack detection

### Next-Gen Phase 4: Enterprise ✓

**Status: Complete**

- [x] Federated learning with differential privacy
- [x] Virtual patching for CVEs
- [x] Threat intelligence integration
- [x] Advanced metrics (Prometheus, OpenTelemetry)
- [x] Production hardening (panic hooks, health checks, graceful shutdown)

---

## Completed Milestones (continued)

### v0.6.0 - WebSocket Support ✓

**Status: Complete**

Added WebSocket frame inspection for detecting attacks in WebSocket traffic.

- [x] Implement `on_websocket_frame()` handler
- [x] Add WebSocket configuration (`WebSocketConfig`)
- [x] Add `--websocket-inspection` CLI flag
- [x] Support fragmented message accumulation
- [x] Add 27 WebSocket inspection tests
- [x] Support text and binary frame inspection
- [x] Detect-only and block modes

---

### v0.7.0 - CI/CD & Quality ✓

**Status: Complete (Disabled)**

GitHub Actions workflows added but disabled to conserve minutes. Change `if: false` to `if: true` in workflow files to enable.

- [x] Add GitHub Actions CI workflow (check, test, fmt, clippy)
- [x] Automated testing on PR (disabled)
- [x] Code coverage reporting (cargo-llvm-cov, Codecov)
- [x] Automated releases (multi-platform builds, crates.io publish)

---

## Upcoming Roadmap

### v0.8.0 - Paranoia Level Rules

**Priority: Medium**

Expand rule coverage for higher paranoia levels.

- [ ] Paranoia level 2 rules (medium confidence)
- [ ] Paranoia level 3 rules (low confidence)
- [ ] Paranoia level 4 rules (maximum sensitivity)
- [ ] Update CRS compatibility tests

### v0.9.0 - Schema Validation

**Priority: Medium**

- [ ] OpenAPI specification parsing and validation
- [ ] GraphQL schema validation
- [ ] Request/response schema enforcement

### v1.0.0 - Production Ready

**Priority: High**

- [ ] Performance optimization (<5ms p99 for 500 rules)
- [ ] Memory optimization (<50MB steady state)
- [ ] Production deployment documentation
- [ ] Kubernetes manifests and Helm chart

---

## Non-Goals

These are explicitly out of scope:

- **ModSecurity rule language (SecLang)** - We use native Rust patterns. For SecLang, see [sentinel-agent-modsec](https://github.com/raskell-io/sentinel-agent-modsec)
- **Body content modification** - We block or allow, not sanitize

---

## Compatibility

| Sentinel Version | WAF Agent Version | Status |
|------------------|-------------------|--------|
| 0.1.x | 0.1.x - 0.5.x | Supported |

---

## Contributing

When working on new features:

1. Add unit tests for new detection rules
2. Update README.md with new CLI options
3. Update this ROADMAP.md when completing milestones
4. Run `cargo test && cargo clippy && cargo fmt` before committing
