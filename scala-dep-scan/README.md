<p align="center">
  <img src="https://img.shields.io/badge/language-Rust-orange?style=flat-square" alt="Rust">
  <img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/scala-2.11%20%7C%202.12%20%7C%202.13%20%7C%203-red?style=flat-square" alt="Scala">
</p>

# scala-dep-scan

A fast, zero-dependency Rust CLI for scanning Scala/Play/SBT projects for vulnerable, outdated, and unused dependencies. Built for teams maintaining legacy codebases.

**One binary. No JVM required. Scans in seconds, not minutes.**

```
$ scala-dep-scan /path/to/project --osv

  Dependencies: 54 direct  +  12 transitive
  Risk flags: 7 Critical  2 High  3 Medium  4 Low

  CRITICAL  com.typesafe.play:play-json:2.3.2 [KNOWN-CVE]
    -> Multiple RCE and CSRF vulnerabilities in Play < 2.8
    CVEs: CVE-2019-17598, CVE-2018-6003
    Fix: Upgrade to >= 2.8.0
    10 file(s) reference this dependency

  CRITICAL  mysql:mysql-connector-java:5.1.31 [OSV-ADVISORY]
    -> Improper Access Control in MySQL Connectors Java
    CVEs: GHSA-2xxh-f8r3-hvvr
```

## Why scala-dep-scan?

| Feature                 | scala-dep-scan | sbt-dependency-check |  Snyk   | Dependabot |
| ----------------------- | :------------: | :------------------: | :-----: | :--------: |
| No JVM required         |      yes       |          no          |   no    |     no     |
| Scan speed              |      <5s       |       minutes        | minutes |   async    |
| Unused dep detection    |      yes       |          no          |   no    |     no     |
| Code reference scanning |      yes       |          no          |   no    |     no     |
| Auto-fix unused deps    |      yes       |          no          |   no    |     no     |
| SBOM generation         |      yes       |         yes          |   yes   |     no     |
| Offline mode            |      yes       |          no          |   no    |     no     |
| License compliance      |      yes       |          no          |   yes   |     no     |
| Interactive TUI         |      yes       |          no          |   no    |     no     |
| Multi-module SBT        |      yes       |         yes          |   yes   |    yes     |
| CI exit codes           |      yes       |         yes          |   yes   |     no     |
| Single binary           |      yes       |          no          |   no    |     no     |
| Free & open source      |      yes       |         yes          |   no    |    yes     |

## Quick Start

### Install

```bash
# macOS (Homebrew)
brew install humancto/tap/scala-dep-scan

# From source (any platform with Rust)
cargo install --path .

# Pre-built binary (Linux x86_64)
chmod +x scala-dep-scan-linux-x86_64
./scala-dep-scan-linux-x86_64 /path/to/project

# macOS from source (one-time setup)
./install-mac.sh
```

### Basic Usage

```bash
# Scan current directory
scala-dep-scan .

# Full scan with OSV advisory lookup
scala-dep-scan /path/to/project --osv

# Show only HIGH+ severity
scala-dep-scan . -s high

# JSON output for CI
scala-dep-scan . -f json | jq '.summary'

# Interactive TUI explorer
scala-dep-scan . --tui

# Quiet mode for CI (exit code only)
scala-dep-scan . -q -s critical
```

## Features

### Risk Detection

Three-tier vulnerability detection:

1. **Embedded database** - 20+ known-bad dependencies (Log4Shell, Spring4Shell, Jackson deserialization, commons-collections RCE, etc.)
2. **Staleness heuristics** - Pre-release versions, date-versioned artifacts, deprecated packages
3. **OSV.dev API** - Live advisory lookup against the Open Source Vulnerability database (`--osv` flag)

```bash
# Full scan with network advisory lookup
scala-dep-scan . --osv

# With response caching (24h default TTL)
scala-dep-scan . --osv           # first run: queries API
scala-dep-scan . --osv           # second run: uses cache
scala-dep-scan . --osv --no-cache  # bypass cache
```

### Unused Dependency Detection

Deep symbol-level analysis identifies dependencies that are:

- **Unused** - No imports, no symbol references anywhere in code
- **Dead imports** - Imported but never actually called
- **Active** - Symbols confirmed used in code
- **Runtime-only** - Injected at runtime (Guice, logback, test frameworks)

```bash
# Show usage analysis
scala-dep-scan . --unused

# Auto-remove unused deps from build.sbt
scala-dep-scan . --fix-unused --dry-run   # preview changes
scala-dep-scan . --fix-unused             # apply changes (creates .bak backup)
```

### Dependency Graph

Visualize your dependency tree in multiple formats:

```bash
# Colorful ASCII tree in terminal (default)
scala-dep-scan .

# Graphviz DOT file
scala-dep-scan . --dot deps.dot
dot -Tsvg deps.dot -o deps.svg   # render to SVG

# JSON adjacency list
scala-dep-scan . --graph-json deps.json
```

### Code Reference Scanning

Finds every `.scala` and `.java` file that imports flagged dependencies, showing exactly where risky code lives:

```
  CRITICAL  com.typesafe.play:play-json:2.3.2 [KNOWN-CVE]
    10 file(s) reference this dependency:
      .../StickerImageActor.scala:16 -> play.api.libs.json.Json
      .../RedisBrowseNodeProducer.scala:9 -> play.api.libs.json.Json
      .../OfferPublisherActor.scala:20 -> play.api.libs.json.Json
      ... and 7 more
```

### Config & Ignore File

Acknowledge known risks and set project-level policy:

```bash
# Generate config with all current findings pre-populated
scala-dep-scan . --init

# Edit .scala-dep-scan.yaml to acknowledge accepted risks
```

```yaml
# .scala-dep-scan.yaml
version: 1
severity_threshold: low
ignore:
  - coord: "com.typesafe.play:play"
    reason: "Migration to Play 2.8 scheduled for Q2"
    expires: "2026-06-01"
  - cve: "CVE-2015-6420"
    reason: "Not exploitable in our deployment"
    expires: "2026-12-31"
```

### SBOM Generation

Generate Software Bill of Materials in industry-standard formats:

```bash
# CycloneDX 1.5 JSON
scala-dep-scan . --sbom cyclonedx --sbom-output sbom-cdx.json

# SPDX 2.3 JSON
scala-dep-scan . --sbom spdx --sbom-output sbom-spdx.json
```

### License Compliance

Scan and enforce license policies:

```bash
# Show license info for all dependencies
scala-dep-scan . --license

# Enforce license policy
scala-dep-scan . --license --license-policy "allow:MIT,Apache-2.0 deny:GPL-3.0"
```

### Upgrade Advisor

Get actionable migration guidance with effort estimates:

```bash
scala-dep-scan . --upgrade-plan
```

```
  Upgrade Plan (prioritized by risk and effort):

  1. com.typesafe.play:play  2.3.2 -> 2.8.19
     Risk: CRITICAL | Effort: ~40 hours | 193 code references
     Breaking changes:
       - play.api.mvc.Controller removed, use BaseController
       - play.api.libs.json.Json.parse throws on invalid JSON
       - Configuration API changed to typesafe config
     Migration guide: https://www.playframework.com/documentation/2.8.x/Migration28

  2. mysql:mysql-connector-java  5.1.31 -> 8.0.33
     Risk: CRITICAL | Effort: ~4 hours | 27 code references
     Breaking changes:
       - Package renamed to com.mysql.cj.jdbc
       - SSL enabled by default
```

### Staleness Scoring

Quantify tech debt with version age analysis:

```bash
scala-dep-scan . --staleness
```

### Policy-as-Code

Define and enforce organizational dependency policies:

```yaml
# .scala-dep-scan.yaml
policies:
  - name: "no-ancient-deps"
    rule: "version_age_months < 36"
    severity: high
    message: "Dependencies must be updated within 3 years"
  - name: "no-pre-release"
    rule: "version !~ /^0\\./"
    severity: medium
```

```bash
scala-dep-scan . --policy org-policy.yaml
```

### HTML Dashboard

Generate shareable reports:

```bash
scala-dep-scan . --html report.html
```

Self-contained single HTML file with executive summary, interactive dependency tree, searchable risk table, and usage analysis charts.

### Scan Comparison / Diff

Track remediation progress across commits:

```bash
# Save baseline
scala-dep-scan . --save-baseline baseline.json

# Compare against baseline (e.g., in PR)
scala-dep-scan . --compare baseline.json
# Shows: 2 NEW findings, 3 RESOLVED, 11 UNCHANGED
# Exit code: fail only on NEW critical/high
```

### Interactive TUI Explorer

Navigate dependencies interactively:

```bash
scala-dep-scan . --tui
```

Three-panel terminal UI with:

- Scrollable dependency list with severity icons
- Detail view with risk info, CVEs, usage, code references
- Search, filter by severity, sort by name/risk/usage
- Keyboard-driven: `j/k` navigate, `/` search, `f` filter, `q` quit

### CI Integration

```yaml
# GitHub Actions
- name: Scan dependencies
  run: |
    scala-dep-scan . --osv -s high -q
    # exits 1 on HIGH, 2 on CRITICAL

# Generate CI config automatically
scala-dep-scan --generate-ci github > .github/workflows/dep-scan.yml
scala-dep-scan --generate-ci gitlab > .gitlab-ci.yml
```

Exit codes:

- `0` - Clean (no HIGH/CRITICAL findings)
- `1` - HIGH severity findings detected
- `2` - CRITICAL severity findings detected

### Multi-Module SBT Projects

Automatically detects multi-module builds:

```bash
scala-dep-scan /path/to/monorepo
# Scans all subprojects, groups findings by module
```

Supports:

- `build.sbt` with `lazy val` subprojects
- `project/Build.scala`
- `.dependsOn()` and `.aggregate()` relationships

## Output Formats

### Terminal (default)

Color-coded ASCII tree + risk findings with CVE IDs, fix suggestions, and code references.

### JSON (`-f json`)

```json
{
  "summary": { "critical": 3, "high": 5, "medium": 2, "low": 4 },
  "risk_flags": [...],
  "code_references": { "org:name": [...] },
  "graph": { "nodes": [...], "edges": [...] }
}
```

### DOT graph (`--dot`)

Graphviz format with color-coded risk nodes. Render with `dot -Tsvg`.

### HTML (`--html`)

Self-contained dashboard report.

### SBOM (`--sbom`)

CycloneDX 1.5 or SPDX 2.3 JSON.

## Architecture

```
src/
├── main.rs          # CLI entry, orchestration
├── types.rs         # Shared data structures
├── config.rs        # Config/ignore file (.scala-dep-scan.yaml)
├── parser/mod.rs    # build.sbt + lockfile parsers (regex-based)
├── risk.rs          # Risk engine: known-bad DB + heuristics + OSV
├── graph.rs         # petgraph dep graph + DOT/ASCII/JSON renderers
├── scanner.rs       # Scala/Java import reference scanner
├── report.rs        # Terminal + JSON report formatters
├── rewriter.rs      # build.sbt rewriter (--fix-unused)
├── sbom.rs          # SBOM generation (CycloneDX, SPDX)
├── license.rs       # License compliance checking
├── staleness.rs     # Dependency age/staleness scoring
├── advisor.rs       # Upgrade path advisor with migration guides
├── policy.rs        # Policy-as-code engine
├── html_report.rs   # HTML dashboard generator
├── diff.rs          # Scan diff/comparison mode
├── ci_templates.rs  # CI config generators
└── tui.rs           # Interactive TUI explorer (ratatui)
data/
└── risky_deps.json  # Embedded risk database (compiled into binary)
tests/
└── *.rs             # Comprehensive test suite
```

## Risk Database

Covers:

- Play Framework (RCE, CSRF)
- Akka HTTP (request smuggling, DoS)
- Log4j / Log4Shell (RCE)
- Spring4Shell (RCE)
- Jackson (deserialization)
- commons-collections (Java deserialization RCE)
- Netty (request smuggling)
- SnakeYAML (DoS, RCE)
- PostgreSQL driver (SQL injection)
- MySQL connector (unauthorized access)
- Guava (path traversal)
- Bouncy Castle (crypto weaknesses)
- And more via OSV.dev API

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for your changes
4. Run the test suite (`cargo test`)
5. Submit a pull request

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](../LICENSE) for details.

## Acknowledgements

- [OSV.dev](https://osv.dev/) for vulnerability advisory data
- [petgraph](https://github.com/petgraph/petgraph) for dependency graph algorithms
- [ratatui](https://github.com/ratatui-org/ratatui) for the terminal UI framework
- [clap](https://github.com/clap-rs/clap) for CLI argument parsing
