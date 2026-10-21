<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-dark.svg">
      <img alt="Zentinel" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-light.svg" height="52">
    </picture>
  </a>
</p>

<h3 align="center">WAF agent</h3>

<p align="center">Scores request paths, query strings, headers and bodies against Zentinel's own pure-Rust attack rules and blocks above an anomaly threshold.</p>

<p align="center">
  <a href="https://github.com/zentinelproxy/zentinel-agent-waf/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zentinelproxy/zentinel-agent-waf/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-9b4d8a?style=flat&labelColor=1f161e">
  <img alt="Rust: 1.94.1+" src="https://img.shields.io/badge/rust-1.94.1%2B-f68d31?style=flat&labelColor=1f161e&logo=rust&logoColor=white">
  <img alt="Agent protocol: v2" src="https://img.shields.io/badge/agent%20protocol-v2-f68d31?style=flat&labelColor=1f161e">
</p>

<p align="center">
  <a href="https://registry.zentinelproxy.io/waf/">Registry</a> &middot;
  <a href="https://docs.zentinelproxy.io">Docs</a> &middot;
  <a href="https://github.com/zentinelproxy">All repositories</a>
</p>

A web application firewall with its own rule set, written in Rust with no C
dependencies. It does not read SecLang: rules are compiled into the agent and
selected by category and paranoia level. Each match adds to an anomaly score;
the request is blocked when the score reaches the threshold. For the OWASP CRS
use [zentinel-agent-zentinelsec](https://github.com/zentinelproxy/zentinel-agent-zentinelsec)
(pure Rust) or [zentinel-agent-modsec](https://github.com/zentinelproxy/zentinel-agent-modsec)
(C libmodsecurity) instead.

> **Known limitation:** the released binary (0.3.0, which
> `zentinel bundle install waf` also installs) does not speak the current agent
> protocol: the proxy's handshake fails with `Invalid message format` and every
> request gets a 503. Build from source until a new release ships.

## Quick start

```bash
# Build from source (see Install), then:
zentinel-waf-agent --socket /var/run/zentinel/waf.sock
```

Then point Zentinel at the socket. Request bodies reach agents only when the
top-level `waf` block enables body inspection:

```kdl
system {
    worker-threads 0
}

listeners {
    listener "http" {
        address "127.0.0.1:8080"
        protocol "http"
    }
}

// Request bodies reach agents only when this block enables them.
waf {
    mode "off"
    body-inspection {
        inspect-request-body #true
        max-inspection-bytes 1048576
    }
}

agents {
    agent "waf" type="waf" {
        unix-socket "/var/run/zentinel/waf.sock"
        events "request_headers" "request_body"
        timeout-ms 200
        failure-mode "closed"
    }
}

filters {
    filter "waf" {
        type "agent"
        agent "waf"
        failure-mode "closed"
    }
}

routes {
    route "default" {
        matches {
            path-prefix "/"
        }
        upstream "backend"
        filters "waf"
    }
}

upstreams {
    upstream "backend" {
        target "127.0.0.1:3000"
    }
}
```

`failure-mode "closed"` on the filter rejects requests while the agent is
unreachable; use `"open"` to forward them uninspected instead.

```bash
curl -i 'http://127.0.0.1:8080/?q=%3Cscript%3Ealert(1)%3C/script%3E'   # 403
curl -i -d "id=1' OR '1'='1" http://127.0.0.1:8080/                     # 403
```

## Install

### From source (recommended for now)

The crate takes `zentinel-agent-protocol` from a sibling checkout of
[zentinel](https://github.com/zentinelproxy/zentinel) (a path dependency), so
clone both side by side. Building needs `protoc`.

```bash
git clone https://github.com/zentinelproxy/zentinel
git clone https://github.com/zentinelproxy/zentinel-agent-waf
cd zentinel-agent-waf
cargo build --release
sudo install -m 0755 target/release/zentinel-waf-agent /usr/local/bin/
```

The path dependency is also why neither `cargo install zentinel-agent-waf` (it
is not on crates.io) nor `cargo install --git` works.

### Bundle

```bash
zentinel bundle install waf
```

Installs release 0.3.0, which does not work with the current proxy (see Known
limitation). See the [bundle documentation](https://docs.zentinelproxy.io/deployment/bundle/).

### Release binaries

[Release 0.3.0](https://github.com/zentinelproxy/zentinel-agent-waf/releases/tag/v0.3.0)
ships `linux-x86_64`, `linux-aarch64` and `darwin-aarch64`, with the same
limitation.

## Configuration

The agent is configured with command-line flags or environment variables. A
`config { }` block on the proxy's `agent` definition does not reach it.

| Option | Environment | Default | Meaning |
|---|---|---|---|
| `--socket` | `AGENT_SOCKET` | `/tmp/zentinel-waf.sock` | Unix socket to listen on |
| `--grpc-address` | `AGENT_GRPC_ADDRESS` | unset | Listen on gRPC at this address instead of the socket |
| `--paranoia-level` | `WAF_PARANOIA_LEVEL` | `1` | 1 to 4; higher levels add lower-confidence rules |
| `--sqli` | `WAF_SQLI` | `true` | SQL injection rules |
| `--xss` | `WAF_XSS` | `true` | Cross-site scripting rules |
| `--path-traversal` | `WAF_PATH_TRAVERSAL` | `true` | Path traversal rules |
| `--command-injection` | `WAF_COMMAND_INJECTION` | `true` | Command injection rules |
| `--protocol` | `WAF_PROTOCOL` | `true` | Protocol, request smuggling and scanner rules |
| `--block-mode` | `WAF_BLOCK_MODE` | `true` | Block at the threshold; `false` is detect-only |
| `--exclude-paths` | `WAF_EXCLUDE_PATHS` | none | Comma-separated path prefixes that skip inspection |
| `--body-inspection` | `WAF_BODY_INSPECTION` | `true` | Inspect request bodies |
| `--max-body-size` | `WAF_MAX_BODY_SIZE` | `1048576` | Largest body inspected, in bytes |
| `--response-inspection` | `WAF_RESPONSE_INSPECTION` | `false` | Scan response bodies (detect only, never blocks) |
| `--websocket-inspection` | `WAF_WEBSOCKET_INSPECTION` | `false` | Scan WebSocket frames (add the `websocket_frame` event on the proxy side) |
| `--websocket-text-frames` | `WAF_WEBSOCKET_TEXT_FRAMES` | `true` | Inspect text frames |
| `--websocket-binary-frames` | `WAF_WEBSOCKET_BINARY_FRAMES` | `false` | Inspect binary frames |
| `--websocket-max-frame-size` | `WAF_WEBSOCKET_MAX_FRAME_SIZE` | `65536` | Largest frame inspected, in bytes |
| `-v`, `--verbose` | `WAF_VERBOSE` | `false` | Debug logging |

The boolean options are switches: `--block-mode` cannot take a value, so
`--block-mode false` is rejected. To turn one off, set the environment
variable, e.g. `WAF_BLOCK_MODE=false`.

The rule categories SSTI, LDAP injection, XPath injection, SSRF and insecure
deserialization are always loaded. Proxy-side agent options are in the
[agents reference](https://docs.zentinelproxy.io/configuration/agents/).

## How it works

**Rules.** 146 rules at paranoia level 1, rising to 284 at level 4 (counted
from `rules::load_rules` with default settings). They cover SQL injection, XSS,
path traversal, command injection, server-side template injection, LDAP and
XPath injection, SSRF, insecure deserialization, protocol attacks, request
smuggling and scanner detection. Patterns are grouped into regex automata, so a
value is matched against a group at once rather than rule by rule.

**Scoring.** Each match contributes its rule's score times a severity
multiplier and a location weight:

| Severity | Multiplier | | Location | Weight |
|---|---|---|---|---|
| Critical | 2.0 | | Query string | 1.5 |
| High | 1.5 | | WebSocket frame | 1.4 |
| Medium | 1.0 | | Path | 1.2 |
| Low | 0.7 | | Body | 1.2 |
| Info | 0.3 | | Header | 1.0 |

A total of 25 or more blocks; 10 to 24 is logged and passed.

| Outcome | What the agent returns |
|---|---|
| Score ≥ 25, block mode | `403 Forbidden`, response headers `X-WAF-Blocked: true`, `X-WAF-Rule` (first rule ID), `X-WAF-Score` |
| Score 10 to 24, or detect-only | Allow, with `X-WAF-Detected` (rule IDs) and `X-WAF-Score` added to the request sent upstream |
| Response body match | Allow, with `X-WAF-Response-Detected` on the response |

The agent also reports request, block and detection counters to the proxy
through the agent protocol's metrics report; it serves no HTTP endpoint of its
own.

**Not wired in yet.** The source tree also contains modules for API security
(GraphQL, JWT, JSON depth), bot detection, credential-stuffing protection,
sensitive-data detection, threat intelligence, virtual patching, supply-chain
checks, federated learning, an ML classifier and a plugin registry. In this
version none of them runs on a request: they are either never called from the
request path or switched off with no flag to enable them. Treat them as work in
progress, not features. [`ROADMAP.md`](ROADMAP.md) has the plan.

## Development

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo bench            # Criterion benchmarks in benches/
```

Building needs Rust 1.94.1+, `protoc`, and the zentinel checkout next to this
one.

## Related

- [Registry page](https://registry.zentinelproxy.io/waf/)
- [zentinel-agent-zentinelsec](https://github.com/zentinelproxy/zentinel-agent-zentinelsec): OWASP CRS on a pure-Rust engine
- [zentinel-agent-modsec](https://github.com/zentinelproxy/zentinel-agent-modsec): OWASP CRS on the C libmodsecurity
- [Agent protocol v2](https://docs.zentinelproxy.io/agents/v2/)
- [Zentinel](https://github.com/zentinelproxy/zentinel)

## License

Apache-2.0, see [`LICENSE`](LICENSE).

---

<p align="center">
  <sub>Part of <a href="https://zentinelproxy.io">Zentinel</a>, the security-first reverse proxy. The shisa guards the gate.</sub>
</p>
