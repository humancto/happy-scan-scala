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

    0 Unused    0 Dead import    49 Active    5 Runtime    3 Orphaned in lock.sbt    329 Linked transitive
```

## Real-World Tested

Validated against **39 production Scala/Play microservices** (1,083 direct + 8,867 transitive dependencies):

| Metric                         | Result                                       |
| ------------------------------ | -------------------------------------------- |
| Risk flags detected            | 2,328 across 39 repos                        |
| Critical vulnerabilities       | 597                                          |
| Unused dep false positive rate | 0% (20 flagged, all verified true positives) |
| Scan time per repo             | <3 seconds                                   |
| Transitive deps discovered     | 8,867 via lock.sbt parsing                   |

## Why scala-dep-scan?

| Feature                 | scala-dep-scan | sbt-dependency-check |  Snyk   | Dependabot |
| ----------------------- | :------------: | :------------------: | :-----: | :--------: |
| No JVM required         |      yes       |          no          |   no    |     no     |
| Scan speed              |      <5s       |       minutes        | minutes |   async    |
| Unused dep detection    |      yes       |          no          |   no    |     no     |
| Orphan detection        |      yes       |          no          |   no    |     no     |
| Transitive dep scanning |      yes       |         yes          |   yes   |    yes     |
| Code reference scanning |      yes       |          no          |   no    |     no     |
| Auto-fix unused deps    |      yes       |          no          |   no    |     no     |
| SBOM generation         |      yes       |         yes          |   yes   |     no     |
| Offline mode            |      yes       |          no          |   no    |     no     |
| License compliance      |      yes       |          no          |   yes   |     no     |
| Interactive TUI         |      yes       |          no          |   no    |     no     |
| HTML reports            |      yes       |          no          |   no    |     no     |
| Upgrade advisor         |      yes       |          no          |   no    |     no     |
| Scan diff/baseline      |      yes       |          no          |   no    |     no     |
| Policy-as-code          |      yes       |          no          |   yes   |     no     |
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

## Reading the Report

When you run `scala-dep-scan`, the output has several sections. Here's how to read each one:

### 1. Summary Header

```
  Project: /path/to/project
  Dependencies: 54 direct  +  362 transitive
    i  32 deps from private/internal orgs
  Risk flags: 17 Critical  15 High  16 Medium  33 Low
```

- **Direct deps**: Dependencies declared in your `build.sbt` files
- **Transitive deps**: Dependencies pulled in via `lock.sbt` or lockfiles (your deps' deps)
- **Private/internal orgs**: Dependencies from your company's packages -- can't be checked against public vulnerability databases, so they're reported separately
- **Risk flags**: Total findings grouped by severity

### 2. Dependency Tree

```
  ├── com.fasterxml.jackson.core:jackson-databind:2.9.8 [HIGH]
  ├── log4j:log4j:1.2.17 [CRITICAL]
  └── com.typesafe.play:play-json:2.6.14 [CRITICAL]
```

Color-coded ASCII tree showing all dependencies and their risk level at a glance. Use `--no-tree` to hide, `--tree-depth N` to control depth.

### 3. Risk Findings

```
 CRITICAL   com.typesafe.play:play-json:2.6.14 [KNOWN-CVE]
   -> Multiple RCE and CSRF vulnerabilities in Play < 2.8
   CVEs: CVE-2019-17598, CVE-2018-6003
   Fix: Upgrade to >= 2.8.0
   10 file(s) reference this dependency:
     .../StickerImageActor.scala:16 -> play.api.libs.json.Json
```

Each finding shows:

- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Coordinate**: `org:name:version`
- **Tag**: `[KNOWN-CVE]` (embedded DB), `[OSV-ADVISORY]` (live lookup), `[OUTDATED]` (staleness)
- **Reason**: Human-readable explanation
- **CVEs**: Specific vulnerability identifiers
- **Fix**: Recommended action
- **Code references**: Exact files and line numbers where the risky dep is imported

### 4. Usage Analysis

```
  3 Unused   0 Dead import   49 Active   5 Runtime

  UNUSED -- no imports, no symbol references found
  ---
  x com.example:unused-lib:1.0.0
    -> Remove from build.sbt to reduce attack surface & build time
```

- **Unused**: No trace of this dependency anywhere in your code -- safe to remove
- **Dead import**: Imported but the symbols are never actually called
- **Active**: Confirmed used with symbol reference counts
- **Runtime**: Framework deps injected at runtime (Guice, logback, HikariCP) -- not false-flagged as unused

### 5. HTML Dashboard (`--html report.html`)

Generates a self-contained HTML file you can open in any browser or share with your team. Includes:

- **Executive summary cards**: Critical/High/Medium/Low counts at a glance
- **Searchable risk table**: Sort by severity, search by dependency name, click to expand
- **Dependency tree**: Collapsible direct + transitive dep tree
- **Usage pie chart**: Visual breakdown of Active/Dead Import/Unused/Runtime
- **Code references**: Expandable sections showing exact file + line references

The HTML report uses a dark theme with color-coded severity badges. Everything is in a single file -- no external CSS/JS dependencies.

### Exit Codes

- `0` -- No HIGH or CRITICAL findings
- `1` -- HIGH severity findings detected
- `2` -- CRITICAL severity findings detected

Use `-q` (quiet) mode in CI to suppress all output and rely only on exit codes.

## How Scoring Works

### Risk Scoring Methodology

Every dependency is evaluated through a **three-tier risk engine**. A dependency can trigger multiple flags simultaneously (e.g., a known CVE AND an OSV advisory).

**Tier 1: Embedded Known-Bad Database (offline, instant)**

The binary ships with 87 curated entries in `data/risky_deps.json`. Each entry specifies:

- `org` + `name` — Maven coordinate to match
- `risky_below` — Version threshold (anything below this version is flagged)
- `severity` — CRITICAL / HIGH / MEDIUM / LOW
- `cve_ids` — Specific CVE identifiers
- `reason` — Human-readable explanation
- `fix_suggestion` — Recommended upgrade path

Version comparison uses semver with loose parsing: `2.3.10-SNAPSHOT` is parsed as `2.3.10`, `2.8.+` as `2.8.0`, and padded versions like `2.8` become `2.8.0`. If a dependency's version is below the `risky_below` threshold, a `[KNOWN-CVE]` flag is emitted.

**Tier 2: Staleness Heuristics (offline, instant)**

Dependencies are checked for red-flag patterns even if they're not in the known-bad database:

- **Pre-release versions** (`0.x.y`) — flagged as LOW risk. Production code shouldn't depend on unstable APIs.
- **Date-versioned artifacts** — versions containing dates before 2018 (e.g., `20150601`) are flagged as MEDIUM risk, indicating 5+ year old code.
- **Known deprecated artifacts** — specific Maven coordinates that have been superseded (e.g., `log4j:log4j` → logback, `commons-lang:commons-lang` → commons-lang3, `org.codehaus.jackson` → `com.fasterxml.jackson`). Flagged as MEDIUM with migration guidance.

**Tier 3: OSV.dev Live Lookup (network required, `--osv` flag)**

When enabled, every dependency is queried against the [OSV.dev API](https://osv.dev/) — the largest open vulnerability database with 8,000+ Maven advisories. The query sends `ecosystem: "Maven"`, `name: "org:artifact"`, and `version` to get real-time advisory data.

Severity is derived from CVSS v3 scores in the advisory:

- Score 9-10 → CRITICAL
- Score 7-8 → HIGH
- Score 4-6 → MEDIUM
- Score 1-3 → LOW

Responses are cached locally (`~/.cache/scala-dep-scan/osv/`) with a 24-hour TTL. Use `--no-cache` to force fresh lookups.

**Severity Levels**

| Level    | Meaning                                                | Exit Code |
| -------- | ------------------------------------------------------ | --------- |
| CRITICAL | Known RCE, authentication bypass, or data exfiltration | 2         |
| HIGH     | Significant vulnerability with known exploit vectors   | 1         |
| MEDIUM   | Vulnerability requiring specific conditions to exploit | 0         |
| LOW      | Minor issue, pre-release version, or informational     | 0         |

### Unused Detection Methodology

Dependencies are classified as **Unused**, **Dead Import**, **Active**, or **Runtime-only** using a 4-pass analysis:

**Pass 1: Import Scanning**

All `.scala` and `.java` files are scanned for `import` statements. Each dependency is mapped to its known Java/Scala package prefixes (e.g., `com.typesafe.play:play-json` → `play.api.libs.json`). If an import matches a dependency's package prefix, that dependency is marked as having imports.

The mapping covers 50+ library profiles with hand-curated package-to-artifact mappings. For dependencies without a known profile, the tool generates package prefixes from the Maven coordinate (e.g., `com.example:my-lib` → `com.example.my`, `com.example.mylib`).

**Pass 2: Symbol Profiling**

Beyond imports, the tool maintains a symbol database mapping artifacts to well-known class and trait names. For example, `com.typesafe.play:play-json` maps to symbols like `Json`, `JsValue`, `Reads`, `Writes`, `Format`. If any of these symbols appear in source code, the dependency is marked as having symbol references.

This catches cases where a library is used via wildcard imports (`import play.api.libs.json._`) and then referenced by class name (`Json.parse(...)`) deep in the code.

**Pass 3: Body Analysis**

For dependencies that have imports but whose symbols might not be in the curated database, the tool scans the actual code body (not just import lines) for references to the imported packages and their classes. This confirms that imported symbols are actually _used_, not just imported and forgotten.

**Pass 4: Fallback Grep**

As a final safety net, ALL source files (`.scala`, `.java`, `.conf`, `.xml`, `.properties`, `.sbt`) are searched for any reference to the artifact name or its likely package components. This catches dependencies used in:

- Configuration files (`application.conf`, `logback.xml`)
- SBT plugin references
- String-based class loading (`Class.forName(...)`)
- Annotation processors

The fallback also strips common suffixes (`client`, `models`, `utils`, `core`, `api`, `commons`) from artifact names. For example, `accountserviceclient` also searches for `accountservice`, catching cases where the package name drops the suffix.

**Runtime-Only Classification**

42 known runtime-only patterns are pre-configured and never flagged as unused. These include:

- **DI frameworks**: Guice, scala-guice, Spring context
- **Logging backends**: logback, slf4j, logstash-logback
- **JDBC pools**: HikariCP, play-jdbc
- **Test frameworks**: ScalaTest, specs2, JUnit, Mockito
- **Compiler plugins**: wartremover, scalameta
- **Cache/migration**: ehcache, Flyway, Liquibase
- **JDBC drivers**: H2, PostgreSQL, MySQL (loaded via config, not import)
- **WebJars**: All `org.webjars:*` (referenced in HTML templates, not Scala code)
- **Play runtime**: play-server, play-netty-server, play-slick, play-slick-evolutions

These dependencies are wired at runtime through reflection, classpath scanning, or configuration files — not through explicit `import` statements. Flagging them as unused would be a false positive.

**Final Verdicts**

| Verdict         | Meaning                                        | Action                                     |
| --------------- | ---------------------------------------------- | ------------------------------------------ |
| **Unused**      | No trace in any source file after all 4 passes | Safe to remove from `build.sbt`            |
| **Dead Import** | Imported but symbols never called in code body | Review — may be removable                  |
| **Active**      | Confirmed used with symbol reference count     | Keep — actively referenced in code         |
| **Runtime**     | Matched runtime-only pattern list              | Keep — required at runtime, not via import |

### build.sbt vs lock.sbt Analysis

The scanner analyzes **both** `build.sbt` (direct deps) and `lock.sbt` (transitive pinned deps) independently:

**build.sbt** — Your explicitly declared dependencies. The 4-pass analysis determines if each one is actually used in your code. Unused deps here are safe to remove from `build.sbt`.

**lock.sbt** — Generated by `sbt-lock`, this file contains `dependencyOverrides` that pin every resolved dependency to an exact version. Over time these files become bloated with entries that:

- Were pinned for a specific conflict that no longer exists
- Belong to dependencies that were removed from `build.sbt` but left in `lock.sbt`
- Were manually added and forgotten

The scanner runs the same 4-pass analysis on lock.sbt entries, then applies the **Orphan Detection Algorithm** to classify each lock.sbt entry as either linked to an active dep or likely orphaned:

```
  LIKELY ORPHANED IN lock.sbt — no code usage, no link to active dependencies
  ─────────────────────────────────────────────────────
  These pinned versions have no code references AND no org/version link to your
  active direct deps. Removing the pin lets SBT resolve the version (or drop it).

  ✗ org.parboiled:parboiled-core:1.1.7
    → Likely safe to remove — verify with `sbt dependencyTree` to confirm
  ✗ org.pegdown:pegdown:1.6.0
    → Likely safe to remove — verify with `sbt dependencyTree` to confirm

  LINKED TRANSITIVE IN lock.sbt — no direct code usage but linked to active deps
  ─────────────────────────────────────────────────────
  · com.fasterxml.jackson.core:jackson-databind:2.9.9
    ↳ Linked to: com.typesafe.play:play-json (Known chain)
  · io.netty:netty-handler:4.0.56.Final
    ↳ Linked to: com.typesafe.play:play (Known chain)
```

### Orphan Detection Algorithm

The scanner uses **pure static analysis** (no JVM, no `sbt dependencyTree`) to classify each lock.sbt entry. Six heuristics are applied in priority order, followed by a multi-hop propagation pass:

1. **Code-referenced** — If the transitive dep has `Active` or `RuntimeOnly` verdict from usage analysis, it's clearly needed regardless of its transitive relationship.

2. **Known transitive chains** — A curated database of **150+ parent-child dependency relationships** in the Scala/Play/Akka ecosystem. Examples:
   - `com.fasterxml.jackson.*` -> pulled by `com.typesafe.play:play-json`
   - `io.netty:*` -> pulled by `com.typesafe.akka:*` or `com.typesafe.play:play`
   - `org.parboiled:*` -> pulled by `io.spray:*`, `akka-http`, or `pegdown`
   - `org.eclipse.jetty:*` -> pulled by `org.seleniumhq.selenium:*`
   - `com.google.code.findbugs:*` -> pulled by `com.google.guava:*`

3. **Exact org matching** — If a lock.sbt dep shares the exact org string with any active direct dep, it's considered a likely transitive. Example: `io.kamon:kamon-scala-future` linked to `io.kamon:kamon-core`.

4. **Internal dep detection** — Dependencies with non-standard orgs (no dots, e.g. `donkeytron`, `catalogserviceclient`) are identified as internal/private company libraries. If they share a name prefix (8+ chars) with any active internal dep, they're linked as company-internal transitives.

5. **Broad org-prefix matching** — If the dep's 2-segment org prefix (e.g. `com.typesafe`) matches any active dep (including active transitives), it's linked. This catches deps pulled by internal libraries that share an ecosystem prefix.

6. **Version cluster detection** — If 3+ lock.sbt deps share the same org prefix AND exact version string, AND at least one cluster member is already linked/active, the whole cluster is linked. Example: 7 `io.netty:*` entries all at `4.0.56.Final`.

7. **Transitive propagation** — After initial classification, a multi-pass propagation runs (up to 5 iterations) where any orphaned dep whose chain rule parent is itself linked gets propagated. This handles multi-hop chains like `pegdown -> parboiled -> play-doc -> play`.

**If none of the heuristics match after propagation, the entry is classified as `LikelyOrphaned`** — no code references, no org link to active deps, no version cluster, no known chain.

**Accuracy (validated against ivy resolution cache across 12 production repos):**

- 7 of 12 repos: **100% accuracy** (zero false positives, zero false negatives)
- Remaining repos: **100% precision** (never wrongly flags a needed dep) with lower recall on stale version pins that share orgs with active deps

**Important caveats:**

1. **Static analysis is heuristic.** The algorithm cannot guarantee a lock.sbt entry is truly orphaned without running `sbt dependencyTree`. Always verify before removing.

2. **Internal library chains cannot be traced.** If an internal library (e.g. `donkeytron`) pulls in external deps, the scanner cannot trace that chain without running sbt. These deps may be flagged as orphaned even though they're needed.

3. **Pins may exist for security reasons.** A team may have pinned a transitive dep to patch a CVE. Check for known vulnerabilities before removing.

4. **Removing a pin does not remove the dep.** It lets SBT resolve whatever version it wants, which could re-introduce a vulnerable version.

5. **Recommended workflow for lock.sbt cleanup:**
   - Review the "LIKELY ORPHANED" section first -- these are highest confidence
   - Cross-reference with `sbt dependencyTree` for definitive proof
   - For "LINKED TRANSITIVE" entries, the pin is likely still needed but the version may be stale -- check `--staleness`
   - The "linked but unused" count shows how many linked deps have zero code evidence -- these are informational, not actionable without `sbt dependencyTree`

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

# Auto-remove unused deps from build.sbt AND lock.sbt
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

### Staleness Report

See how old your dependencies are compared to latest available versions:

```bash
scala-dep-scan . --staleness
```

```
  == Dependency Staleness Report ==
  3 Current (<6mo)  |  2 Aging (6-18mo)  |  1 Stale (18-36mo)  |  5 Outdated (>36mo)
  8 dependencies have updates available

  DEPENDENCY                                    CURRENT         LATEST          BEHIND   STATUS
  com.typesafe.play:play-json                   2.6.14          2.10.4          ~4       [XX] OUTDATED (48mo)
  log4j:log4j                                   1.2.17          1.2.17          -        [??] UNKNOWN
```

### Upgrade Advisor

Get actionable migration guidance with effort estimates:

```bash
scala-dep-scan . --upgrade-plan
```

```
  Upgrade Plan (prioritized by risk and effort):

  1. [!!!] log4j:log4j -> 1.4.x
     Priority: CRITICAL (Security)  |  Current: 1.2.17  |  Effort: ~6.0h
     Log4j 1.x is EOL since 2015 with known vulnerabilities. Migrate to Logback or Log4j 2.x.
     Breaking changes:
       1. Completely different API - Log4j 1.x API replaced with SLF4J
       2. Configuration format changes: log4j.properties -> logback.xml
       3. Appender classes all different
     Docs: https://logback.qos.ch/manual/migrationFromLog4j.html

  2. [!! ] com.typesafe.play:play -> 2.8.x
     Priority: HIGH (EOL/Deprecated)  |  Current: 2.6.25  |  Effort: ~12.0h
     Play 2.6/2.7 is EOL. Upgrade to 2.8.x for security patches.
```

### Policy-as-Code

Define and enforce organizational dependency policies:

```yaml
# policy.yaml
policies:
  - name: "no-ancient-deps"
    rule: "version_age_months > 36"
    severity: high
    message: "Dependencies must be updated within 3 years"
  - name: "no-pre-release"
    rule: "version =~ /^0\\./"
    severity: medium
```

```bash
scala-dep-scan . --policy policy.yaml
```

### HTML Dashboard

Generate shareable reports:

```bash
scala-dep-scan . --html report.html
```

Self-contained single HTML file with executive summary, interactive dependency tree, searchable risk table, and usage analysis charts. Dark themed, no external dependencies.

### Scan Comparison / Diff

Track remediation progress across commits:

```bash
# Save baseline
scala-dep-scan . --save-baseline baseline.json

# Compare against baseline (e.g., in PR)
scala-dep-scan . --compare baseline.json
# Shows: 2 NEW findings, 3 RESOLVED, 11 UNCHANGED
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

## All CLI Flags

| Flag                       | Description                                                   |
| -------------------------- | ------------------------------------------------------------- |
| `-s, --severity <LEVEL>`   | Minimum severity to report: info, low, medium, high, critical |
| `-f, --format <FORMAT>`    | Output format: terminal (default), json                       |
| `-q, --quiet`              | Suppress progress indicators                                  |
| `--osv`                    | Enable live OSV/NVD advisory lookup (requires network)        |
| `--no-cache`               | Bypass the OSV response cache                                 |
| `--show-deps`              | Show full dependency table                                    |
| `--no-tree`                | Disable ASCII dependency tree                                 |
| `--tree-depth <N>`         | Max depth for ASCII tree (default: 3)                         |
| `--unused`                 | Show full usage analysis detail                               |
| `--fix-unused`             | Auto-remove unused deps from build.sbt AND lock.sbt           |
| `--dry-run`                | Preview --fix-unused changes without modifying files          |
| `--init`                   | Generate .scala-dep-scan.yaml config                          |
| `--dot <PATH>`             | Write Graphviz DOT file                                       |
| `--graph-json <PATH>`      | Write JSON dependency graph                                   |
| `--html <PATH>`            | Generate HTML dashboard report                                |
| `--sbom <FORMAT>`          | Generate SBOM (cyclonedx or spdx)                             |
| `--sbom-output <PATH>`     | Write SBOM to file (default: stdout)                          |
| `--license`                | Show license compliance info                                  |
| `--license-policy <SPEC>`  | Enforce license policy                                        |
| `--staleness`              | Show dependency staleness report                              |
| `--upgrade-plan`           | Show upgrade recommendations                                  |
| `--policy <PATH>`          | Evaluate against a policy YAML file                           |
| `--save-baseline <PATH>`   | Save scan results as baseline                                 |
| `--compare <PATH>`         | Compare scan against saved baseline                           |
| `--generate-ci <PLATFORM>` | Generate CI config (github or gitlab)                         |
| `--tui`                    | Launch interactive TUI explorer                               |

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
    "orphaned_lock_deps": 3,
    "linked_lock_deps": 329,
    "private_deps": 229,
    "private_deps_note": "Private/internal dependencies cannot be scanned against public vulnerability databases"
  },
  "risk_flags": [...],
  "dependency_usage": [
    {"coord": "com.example:lib", "verdict": "Unused", "usage_count": 0},
    {"coord": "com.example:used-lib", "verdict": "Active", "usage_count": 15, "symbols_found": ["Json", "Reads"]}
  ],
  "code_references": { "org:name": [...] },
  "graph": { "nodes": [...], "edges": [...] },
  "transitive_classifications": {
    "com.fasterxml.jackson.core:jackson-databind": {"LinkedTo": {"parent_coord": "...", "reason": "..."}},
    "jmock:jmock": "LikelyOrphaned"
  }
}
```

### DOT graph (`--dot`)

Graphviz format with color-coded risk nodes. Render with `dot -Tsvg`.

### HTML (`--html`)

Self-contained dashboard report with search, sort, and pie charts.

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
+-- orphan.rs        # lock.sbt orphan detection (150+ chain rules)
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
+-- *.rs             # 108 tests covering all modules
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
  url "https://github.com/humancto/happy-scan-scala/archive/refs/tags/v0.4.0.tar.gz"
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

We welcome contributions!

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
