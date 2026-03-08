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

  Project: /path/to/project
  Dependencies: 54 direct  +  362 transitive
    i  32 deps from private/internal orgs -- not scannable against public vuln databases
  Risk flags: 17 Critical  15 High  16 Medium  33 Low

  CRITICAL  com.typesafe.play:play-json:2.3.2 [KNOWN-CVE]
    -> Multiple RCE and CSRF vulnerabilities in Play < 2.8
    CVEs: CVE-2019-17598, CVE-2018-6003
    Fix: Upgrade to >= 2.8.0
    10 file(s) reference this dependency

  CRITICAL  mysql:mysql-connector-java:5.1.31 [OSV-ADVISORY]
    -> Improper Access Control in MySQL Connectors Java
    CVEs: GHSA-2xxh-f8r3-hvvr

  -- Dependency Usage Analysis --

    0 Unused    0 Dead import    49 Active    5 Runtime
```

## Real-World Tested

Validated against **39 production Scala/Play microservices** (1,083 direct + 8,867 transitive dependencies):

| Metric                         | Result                         |
| ------------------------------ | ------------------------------ |
| Risk flags detected            | 2,328 across 39 repos          |
| Critical vulnerabilities       | 597                            |
| Unused dep false positive rate | <5% (43 flagged, all verified) |
| Scan time per repo             | <3 seconds                     |
| Transitive deps discovered     | 8,867 via lock.sbt parsing     |

## Why scala-dep-scan?

| Feature                 | scala-dep-scan | sbt-dependency-check |  Snyk   | Dependabot |
| ----------------------- | :------------: | :------------------: | :-----: | :--------: |
| No JVM required         |      yes       |          no          |   no    |     no     |
| Scan speed              |      <5s       |       minutes        | minutes |   async    |
| Unused dep detection    |      yes       |          no          |   no    |     no     |
| Transitive dep scanning |      yes       |         yes          |   yes   |    yes     |
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
# From crates.io (recommended)
cargo install scala-dep-scan

# macOS (Homebrew)
brew install humancto/tap/scala-dep-scan

# From source
git clone https://github.com/humancto/happy-scan-scala.git
cd happy-scan-scala
cargo install --path .

# Pre-built binaries
# Download from GitHub Releases for your platform
```

### Basic Usage

```bash
# Scan current directory
scala-dep-scan .

# Full scan with OSV advisory lookup (network required)
scala-dep-scan /path/to/project --osv

# Show only HIGH+ severity
scala-dep-scan . -s high

# JSON output for CI pipelines
scala-dep-scan . -f json | jq '.summary'

# Interactive TUI explorer
scala-dep-scan . --tui

# Quiet mode for CI (exit code only)
scala-dep-scan . -q -s critical
```

## Features

### Vulnerability Detection

Three-tier detection engine with 87 embedded rules:

1. **Embedded database** - 87 known-bad dependencies covering Log4Shell, Spring4Shell, Jackson deserialization, commons-collections RCE, H2 RCE, Text4Shell, XStream, Jetty, Netty, BouncyCastle, Apache Shiro, and many more
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

4-pass deep analysis with <5% false positive rate:

1. **Import scanning** - Matches `import` statements to dependency package prefixes
2. **Symbol profiling** - 50+ library profiles mapping artifacts to their CamelCase class names
3. **Body analysis** - Confirms imported symbols are actually called in code
4. **Fallback grep** - Searches all source files (.scala, .java, .conf, .xml, .properties) for artifact name references

Categories:

- **Unused** - No imports, no symbol references, no config references anywhere in code
- **Dead imports** - Imported but symbols never actually called
- **Active** - Symbols confirmed used in code (with reference counts)
- **Runtime-only** - Injected at runtime (Guice, logback, HikariCP, test frameworks) -- not false-flagged

```bash
# Usage analysis is always on -- shown in every scan
scala-dep-scan .

# Auto-remove unused deps from build.sbt
scala-dep-scan . --fix-unused --dry-run   # preview changes
scala-dep-scan . --fix-unused             # apply changes (creates .bak backup)
```

### Transitive Dependency Scanning

Parses both `lock.sbt` (sbt-lock plugin) and Coursier lockfile formats to discover and scan the full transitive dependency tree:

```bash
scala-dep-scan .
# Dependencies: 54 direct  +  362 transitive
# All 416 dependencies scanned for vulnerabilities
```

### Private Dependency Detection

Internal/private org dependencies (e.g. `com.yourcompany:*`) are automatically identified and reported separately. They cannot be scanned against public vulnerability databases, and the tool clearly marks them:

```
  i  32 deps from private/internal orgs -- not scannable against public vuln databases
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
    cargo install scala-dep-scan
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

Automatically detects and scans multi-module builds:

```bash
scala-dep-scan /path/to/monorepo
# Discovers modules/*/build.sbt, project/Dependencies.scala, lock.sbt
# Scans all subprojects, groups findings by module
```

Supports:

- `build.sbt` with `lazy val` subprojects
- `project/Build.scala` and `project/Dependencies.scala`
- `.dependsOn()` and `.aggregate()` relationships
- `lock.sbt` (sbt-lock plugin) for transitive deps
- Nested `modules/*/build.sbt` subprojects

## Output Formats

### Terminal (default)

Color-coded ASCII tree + risk findings with CVE IDs, fix suggestions, code references, and usage analysis.

### JSON (`-f json`)

```json
{
  "summary": {
    "direct_deps": 54,
    "transitive_deps": 362,
    "total_flags": 82,
    "critical": 17,
    "high": 15,
    "medium": 16,
    "low": 33,
    "unused_deps": 0,
    "dead_import_deps": 0,
    "private_deps": 229,
    "private_deps_note": "Private/internal dependencies cannot be scanned against public vulnerability databases"
  },
  "risk_flags": [...],
  "dependency_usage": [
    {"coord": "com.example:lib", "verdict": "Unused", "usage_count": 0},
    {"coord": "com.example:used-lib", "verdict": "Active", "usage_count": 15, "symbols_found": ["Json", "Reads"]}
  ],
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
+-- main.rs          # CLI entry, orchestration
+-- types.rs         # Shared data structures
+-- config.rs        # Config/ignore file (.scala-dep-scan.yaml)
+-- parser/mod.rs    # build.sbt + lock.sbt + lockfile parsers
+-- risk.rs          # Risk engine: known-bad DB + heuristics + OSV
+-- graph.rs         # petgraph dep graph + DOT/ASCII/JSON renderers
+-- scanner.rs       # 4-pass usage analysis + code reference scanner
+-- report.rs        # Terminal + JSON report formatters
+-- rewriter.rs      # build.sbt rewriter (--fix-unused)
+-- sbom.rs          # SBOM generation (CycloneDX, SPDX)
+-- license.rs       # License compliance checking
+-- staleness.rs     # Dependency age/staleness scoring
+-- advisor.rs       # Upgrade path advisor with migration guides
+-- policy.rs        # Policy-as-code engine
+-- html_report.rs   # HTML dashboard generator
+-- diff.rs          # Scan diff/comparison mode
+-- ci_templates.rs  # CI config generators
+-- tui.rs           # Interactive TUI explorer (ratatui)
data/
+-- risky_deps.json  # Embedded risk database (87 entries, compiled into binary)
tests/
+-- *.rs             # 62 tests covering all modules
```

## Risk Database

87 entries covering the most critical JVM vulnerabilities, with verified CVE references. Updated periodically.

| Category            | Libraries                                                                                    | Key CVEs                                       |
| ------------------- | -------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| **Frameworks**      | Play Framework, Spring (core/web/security), Akka HTTP                                        | CVE-2019-17598, CVE-2022-22965, CVE-2024-22257 |
| **Logging**         | Log4j (Log4Shell), Logback (classic + core)                                                  | CVE-2021-44228, CVE-2023-6378                  |
| **Serialization**   | Jackson, XStream, SnakeYAML, Kryo, Gson, Avro, protobuf-java                                 | CVE-2020-36518, CVE-2021-39144, CVE-2024-7254  |
| **Apache Commons**  | collections, text (Text4Shell), compress, fileupload, beanutils, configuration               | CVE-2015-7501, CVE-2022-42889, CVE-2024-26308  |
| **HTTP/Networking** | Netty (handler, codec-http2), Jetty, OkHttp, HttpClient, Undertow, Tomcat, Async HTTP Client | CVE-2021-43797, CVE-2023-44487, CVE-2024-53990 |
| **Databases**       | MySQL, PostgreSQL, H2 (RCE), SQLite, Elasticsearch                                           | CVE-2021-42392, CVE-2022-21724, CVE-2023-31419 |
| **Crypto/Security** | BouncyCastle (bcprov/bcpkix), Apache Shiro (core/web), Nimbus JOSE+JWT                       | CVE-2024-30172, CVE-2023-34478, CVE-2025-53864 |
| **XML/Templating**  | dom4j, Woodstox, Velocity, FreeMarker, Thymeleaf, Xalan, Batik                               | CVE-2020-10683, CVE-2023-38286                 |
| **Document**        | Apache POI, Apache Tika, PDFBox, iText                                                       | CVE-2023-45648                                 |
| **ORM**             | Hibernate (core/validator)                                                                   | CVE-2020-25638                                 |

Plus live lookups via **OSV.dev API** for real-time advisory data on all 8,000+ Maven advisories.

## Publishing

### crates.io

```bash
# Login (one-time)
cargo login

# Publish
cargo publish
```

### Homebrew

Users can install via the Homebrew tap:

```bash
brew tap humancto/tap
brew install scala-dep-scan
```

To set up the tap, create a formula at `humancto/homebrew-tap`:

```ruby
class ScalaDepScan < Formula
  desc "Dependency risk scanner for Scala/Play/SBT projects"
  homepage "https://github.com/humancto/happy-scan-scala"
  url "https://github.com/humancto/happy-scan-scala/archive/refs/tags/v0.3.0.tar.gz"
  license "Apache-2.0"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_match "scala-dep-scan", shell_output("#{bin}/scala-dep-scan --version")
  end
end
```

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for your changes
4. Run the test suite (`cargo test`)
5. Submit a pull request

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## Acknowledgements

- [OSV.dev](https://osv.dev/) for vulnerability advisory data
- [petgraph](https://github.com/petgraph/petgraph) for dependency graph algorithms
- [ratatui](https://github.com/ratatui-org/ratatui) for the terminal UI framework
- [clap](https://github.com/clap-rs/clap) for CLI argument parsing
