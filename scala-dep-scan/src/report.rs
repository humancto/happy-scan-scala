use crate::graph::DepGraph;
use crate::types::{CodeReference, Dependency, RiskFlag, SbtModule, Severity};
use colored::*;
use std::collections::HashMap;

pub struct ReportConfig {
    pub show_tree: bool,
    pub show_code_refs: bool,
    pub min_severity: Severity,
    pub json_output: bool,
}

pub fn print_header() {
    println!();
    println!(
        "{}",
        "╔══════════════════════════════════════════════════════════╗".cyan()
    );
    println!(
        "{}",
        "║         scala-dep-scan  •  dependency risk scanner       ║".cyan()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════════════════╝".cyan()
    );
    println!();
}

/// Count dependencies from private/internal orgs that can't be scanned against public vuln DBs
pub fn count_private_deps(deps: &[Dependency]) -> usize {
    deps.iter().filter(|d| is_private_org(&d.org)).count()
}

fn is_private_org(org: &str) -> bool {
    // Well-known public org prefixes
    let public_prefixes = [
        "org.apache",
        "com.google",
        "com.typesafe",
        "io.netty",
        "com.fasterxml",
        "org.scala-lang",
        "org.slf4j",
        "ch.qos",
        "org.postgresql",
        "mysql",
        "com.amazonaws",
        "software.amazon",
        "org.mongodb",
        "redis.",
        "io.circe",
        "org.http4s",
        "org.typelevel",
        "com.softwaremill",
        "org.specs2",
        "org.scalatest",
        "org.mockito",
        "junit",
        "com.github",
        "io.github",
        "org.yaml",
        "org.bouncycastle",
        "commons-",
        "org.xerial",
        "com.zaxxer",
        "org.flywaydb",
        "org.liquibase",
        "com.h2database",
        "org.eclipse",
        "javax.",
        "jakarta.",
        "io.spray",
        "com.lightbend",
        "org.playframework",
        "org.webjars",
        "io.undertow",
        "org.jboss",
        "io.dropwizard",
        "com.squareup",
        "io.grpc",
        "com.twitter",
        "org.json4s",
        "io.argonaut",
        "com.lihaoyi",
        "dev.zio",
        "org.scalaz",
        "com.chuusai",
        "org.tpolecat",
        "co.fs2",
        "com.datastax",
        "org.apache",
        "org.jetbrains",
        "com.oracle",
        "io.prometheus",
        "io.micrometer",
        "io.opentelemetry",
        "org.ehcache",
        "com.jcraft",
        "org.cvogt",
        "com.hierynomus",
        "com.rockymadden",
        "org.sangria",
        "com.pauldijou",
        "org.bitbucket",
        "com.atlassian",
        "net.logstash",
    ];
    !public_prefixes.iter().any(|p| org.starts_with(p))
}

pub fn print_summary(
    direct_count: usize,
    transitive_count: usize,
    risk_flags: &[RiskFlag],
    project_root: &str,
    ignored_count: usize,
    private_dep_count: usize,
) {
    println!("{} {}", "Project:".bold(), project_root.yellow());
    println!(
        "{} {} direct  +  {} transitive",
        "Dependencies:".bold(),
        direct_count.to_string().cyan(),
        transitive_count.to_string().dimmed()
    );
    if private_dep_count > 0 {
        println!(
            "{}",
            format!(
                "  ℹ  {} deps from private/internal orgs — not scannable against public vuln databases",
                private_dep_count
            )
            .dimmed()
        );
    }

    let critical = risk_flags
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = risk_flags
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium = risk_flags
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low = risk_flags
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();

    let ignored_str = if ignored_count > 0 {
        format!("  ({} ignored via config)", ignored_count)
            .dimmed()
            .to_string()
    } else {
        String::new()
    };

    println!(
        "{} {}  {}  {}  {}{}",
        "Risk flags:".bold(),
        format!("💀 {} Critical", critical).red().bold(),
        format!("🔴 {} High", high).red(),
        format!("🟡 {} Medium", medium).yellow(),
        format!("🟢 {} Low", low).green(),
        ignored_str,
    );
    println!();
}

pub fn print_risk_flags(
    flags: &[RiskFlag],
    code_refs: &HashMap<String, Vec<CodeReference>>,
    min_severity: &Severity,
) {
    let filtered: Vec<&RiskFlag> = flags
        .iter()
        .filter(|f| &f.severity >= min_severity)
        .collect();

    if filtered.is_empty() {
        println!(
            "{}",
            "✅  No risky dependencies found above threshold!"
                .green()
                .bold()
        );
        return;
    }

    // Sort by severity descending
    let mut sorted = filtered.clone();
    sorted.sort_by(|a, b| b.severity.cmp(&a.severity));

    println!(
        "{}",
        "── Risk Findings ────────────────────────────────────────────".bold()
    );
    println!();

    for flag in &sorted {
        let sev_label = match flag.severity {
            Severity::Critical => format!(" {} ", flag.severity.label())
                .on_red()
                .white()
                .bold()
                .to_string(),
            Severity::High => format!(" {} ", flag.severity.label())
                .on_truecolor(200, 80, 0)
                .white()
                .to_string(),
            Severity::Medium => format!(" {} ", flag.severity.label())
                .on_yellow()
                .black()
                .to_string(),
            Severity::Low => format!(" {} ", flag.severity.label())
                .on_green()
                .black()
                .to_string(),
            Severity::Info => format!(" {} ", flag.severity.label())
                .on_blue()
                .white()
                .to_string(),
        };

        let type_badge = format!("[{}]", flag.risk_type.label()).dimmed();

        println!(
            "{}  {} {}",
            sev_label,
            format!("{}:{}", flag.dependency.coord(), flag.dependency.version).bold(),
            type_badge
        );
        println!("   {} {}", "↳".dimmed(), flag.reason.italic());

        if !flag.cve_ids.is_empty() {
            let cves = flag
                .cve_ids
                .iter()
                .map(|c| c.yellow().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            println!("   {} CVEs: {}", "⚑".red(), cves);
        }

        if let Some(fix) = &flag.fix_suggestion {
            println!("   {} {}", "→ Fix:".green().bold(), fix.green());
        }

        // Show code references
        let coord = flag.dependency.coord();
        if let Some(refs) = code_refs.get(&coord) {
            if !refs.is_empty() {
                println!(
                    "   {} {} file(s) reference this dependency:",
                    "📄".dimmed(),
                    refs.len()
                );
                for r in refs.iter().take(3) {
                    // Shorten path for display
                    let short_path = shorten_path(&r.file);
                    println!(
                        "     {}{}:{} → {}",
                        "  ".dimmed(),
                        short_path.cyan(),
                        r.line_number.to_string().dimmed(),
                        r.import_path.dimmed()
                    );
                }
                if refs.len() > 3 {
                    println!("     {} ... and {} more", "  ".dimmed(), refs.len() - 3);
                }
            }
        }

        println!();
    }
}

pub fn print_dep_table(deps: &[Dependency], title: &str) {
    println!(
        "{}",
        format!("── {} ─────────────────────────────────────────────", title).bold()
    );
    for dep in deps {
        let cross = if dep.cross_compiled {
            "%%".dimmed().to_string()
        } else {
            "% ".dimmed().to_string()
        };
        let scope = dep.scope.as_deref().unwrap_or("compile");
        println!(
            "  {} {} {}  ({})",
            dep.org.dimmed(),
            cross,
            format!("{}:{}", dep.name, dep.version).white(),
            scope.dimmed()
        );
    }
    println!();
}

pub fn print_ascii_tree(graph: &DepGraph, risk_map: &HashMap<String, Severity>) {
    let tree = graph.to_ascii_tree(risk_map, 3);
    println!("{}", tree);
}

pub fn print_json_report(
    direct: &[Dependency],
    transitive: &[Dependency],
    flags: &[RiskFlag],
    code_refs: &HashMap<String, Vec<CodeReference>>,
    graph: &DepGraph,
    ignored_count: usize,
    usage_reports: &[crate::types::DepUsageReport],
) {
    use crate::types::UsageVerdict;
    let private_count = count_private_deps(direct) + count_private_deps(transitive);
    let unused_count = usage_reports
        .iter()
        .filter(|r| r.verdict == UsageVerdict::Unused)
        .count();
    let dead_import_count = usage_reports
        .iter()
        .filter(|r| r.verdict == UsageVerdict::DeadImport)
        .count();
    let report = serde_json::json!({
        "summary": {
            "direct_deps": direct.len(),
            "transitive_deps": transitive.len(),
            "total_flags": flags.len(),
            "ignored_flags": ignored_count,
            "private_deps": private_count,
            "private_deps_note": if private_count > 0 { "Private/internal dependencies cannot be scanned against public vulnerability databases" } else { "" },
            "critical": flags.iter().filter(|f| f.severity == Severity::Critical).count(),
            "high": flags.iter().filter(|f| f.severity == Severity::High).count(),
            "medium": flags.iter().filter(|f| f.severity == Severity::Medium).count(),
            "low": flags.iter().filter(|f| f.severity == Severity::Low).count(),
            "unused_deps": unused_count,
            "dead_import_deps": dead_import_count,
        },
        "risk_flags": flags,
        "dependency_usage": usage_reports,
        "code_references": code_refs,
        "graph": serde_json::from_str::<serde_json::Value>(&graph.to_json()).unwrap_or_default(),
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
}

pub fn print_legend() {
    println!(
        "{}",
        "── Legend ──────────────────────────────────────────────────".dimmed()
    );
    println!(
        "  {}  Critical    {}  High    {}  Medium    {}  Low    {}  Direct dep    {}  Transitive",
        "💀".red(),
        "🔴".red(),
        "🟡".yellow(),
        "🟢".green(),
        "📦".cyan(),
        "  ".dimmed()
    );
    println!();
}

pub fn print_usage_report(reports: &[crate::types::DepUsageReport]) {
    use crate::types::UsageVerdict;
    use colored::*;

    println!(
        "{}",
        "── Dependency Usage Analysis ────────────────────────────────".bold()
    );
    println!();

    let unused: Vec<_> = reports
        .iter()
        .filter(|r| r.verdict == UsageVerdict::Unused)
        .collect();
    let dead: Vec<_> = reports
        .iter()
        .filter(|r| r.verdict == UsageVerdict::DeadImport)
        .collect();
    let active: Vec<_> = reports
        .iter()
        .filter(|r| r.verdict == UsageVerdict::Active)
        .collect();
    let runtime: Vec<_> = reports
        .iter()
        .filter(|r| r.verdict == UsageVerdict::RuntimeOnly)
        .collect();

    // Summary bar
    println!(
        "  {}  {}   {}  {}   {}  {}   {}  {}",
        "💀".red(),
        format!("{} Unused", unused.len()).red().bold(),
        "👻".yellow(),
        format!("{} Dead import", dead.len()).yellow().bold(),
        "✅".green(),
        format!("{} Active", active.len()).green(),
        "⚙️ ".dimmed(),
        format!("{} Runtime", runtime.len()).dimmed(),
    );
    println!();

    // Unused deps — never imported, never referenced
    if !unused.is_empty() {
        println!(
            "{}",
            "  💀  UNUSED — no imports, no symbol references found"
                .red()
                .bold()
        );
        println!(
            "{}",
            "  ─────────────────────────────────────────────────────".dimmed()
        );
        for r in &unused {
            println!(
                "  {} {}",
                "✗".red().bold(),
                format!("{}:{}", r.coord, r.version).red()
            );
            println!(
                "    {} Remove from build.sbt to reduce attack surface & build time",
                "→".dimmed()
            );
        }
        println!();
    }

    // Dead imports — imported but symbols never used in file body
    if !dead.is_empty() {
        println!(
            "{}",
            "  👻  DEAD IMPORT — imported but never called in code body"
                .yellow()
                .bold()
        );
        println!(
            "{}",
            "  ─────────────────────────────────────────────────────".dimmed()
        );
        for r in &dead {
            println!(
                "  {} {}",
                "~".yellow().bold(),
                format!("{}:{}", r.coord, r.version).yellow()
            );
            let shown: Vec<_> = r.import_files.iter().take(3).collect();
            for f in shown {
                println!(
                    "    {} imported in {}",
                    "↳".dimmed(),
                    shorten_path(f).cyan()
                );
            }
            if r.import_files.len() > 3 {
                println!(
                    "    {} ... and {} more files",
                    "  ".dimmed(),
                    r.import_files.len() - 3
                );
            }
            println!(
                "    {} Imported but no class/method calls detected in file bodies",
                "→".dimmed()
            );
        }
        println!();
    }

    // Active deps
    if !active.is_empty() {
        println!(
            "{}",
            "  ✅  ACTIVE — symbols confirmed used in code"
                .green()
                .bold()
        );
        println!(
            "{}",
            "  ─────────────────────────────────────────────────────".dimmed()
        );
        for r in &active {
            let sym_preview: String = r
                .symbols_found
                .iter()
                .take(4)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            let more = if r.symbols_found.len() > 4 {
                format!(" +{} more", r.symbols_found.len() - 4)
            } else {
                String::new()
            };

            println!(
                "  {} {}  {} {}{}",
                "✓".green().bold(),
                format!("{}:{}", r.coord, r.version).green(),
                format!("({} refs)", r.usage_count).dimmed(),
                sym_preview.dimmed(),
                more.dimmed()
            );
        }
        println!();
    }

    // Runtime-only
    if !runtime.is_empty() {
        println!(
            "{}",
            "  ⚙️   RUNTIME — injected at runtime, no imports expected"
                .dimmed()
                .bold()
        );
        println!(
            "{}",
            "  ─────────────────────────────────────────────────────".dimmed()
        );
        for r in &runtime {
            println!(
                "  {} {}",
                "○".dimmed(),
                format!("{}:{}", r.coord, r.version).dimmed()
            );
        }
        println!();
    }
}

pub fn print_modules(modules: &[SbtModule]) {
    if modules.is_empty() {
        return;
    }

    println!(
        "{}",
        "── SBT Modules ─────────────────────────────────────────────".bold()
    );
    println!();

    for module in modules {
        println!(
            "  {} {} (path: {})",
            ">>".cyan().bold(),
            module.name.cyan().bold(),
            module.path.dimmed()
        );
        if !module.depends_on.is_empty() {
            println!(
                "     {} dependsOn: {}",
                "↳".dimmed(),
                module.depends_on.join(", ").yellow()
            );
        }
        if !module.aggregates.is_empty() {
            println!(
                "     {} aggregates: {}",
                "↳".dimmed(),
                module.aggregates.join(", ").yellow()
            );
        }
        if !module.deps.is_empty() {
            println!(
                "     {} {} dependencies",
                "↳".dimmed(),
                module.deps.len().to_string().cyan()
            );
            for dep in module.deps.iter().take(5) {
                println!(
                    "       {} {}:{}",
                    "-".dimmed(),
                    dep.coord().dimmed(),
                    dep.version.dimmed()
                );
            }
            if module.deps.len() > 5 {
                println!(
                    "       {} ... and {} more",
                    " ".dimmed(),
                    module.deps.len() - 5
                );
            }
        }
        println!();
    }
}

fn shorten_path(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() > 3 {
        format!("…/{}", parts[parts.len() - 3..].join("/"))
    } else {
        path.to_string()
    }
}
