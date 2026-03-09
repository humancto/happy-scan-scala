mod advisor;
mod ci_templates;
mod config;
mod diff;
mod graph;
mod html_report;
mod license;
mod orphan;
mod parser;
mod policy;
mod report;
mod rewriter;
mod risk;
mod sbom;
mod scanner;
mod staleness;
mod tui;
mod types;

use anyhow::{Context, Result};
use clap::Parser;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use graph::DepGraph;
use types::{Dependency, RiskFlag, Severity, UsageVerdict};

#[derive(Parser, Debug)]
#[command(
    name = "scala-dep-scan",
    about = "Dependency risk scanner for Scala/Play projects",
    long_about = "Scans build.sbt, lock.sbt, and project/*.scala files to identify risky, outdated,\nand unused dependencies, build a dependency graph, and locate related code in your project.",
    version = "0.4.0"
)]
struct Cli {
    /// Path to the Scala project root (default: current directory)
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Minimum severity to report (info, low, medium, high, critical)
    #[arg(short = 's', long = "severity", default_value = "low")]
    min_severity: String,

    /// Output format: terminal (default), json
    #[arg(short = 'f', long = "format", default_value = "terminal")]
    format: String,

    /// Write Graphviz DOT file to this path
    #[arg(long = "dot")]
    dot_output: Option<PathBuf>,

    /// Write JSON graph to this path
    #[arg(long = "graph-json")]
    graph_json_output: Option<PathBuf>,

    /// Enable OSV/NVD advisory lookup (requires network)
    #[arg(long = "osv", default_value_t = false)]
    osv: bool,

    /// Show full dependency table
    #[arg(long = "show-deps", default_value_t = false)]
    show_deps: bool,

    /// Disable colored ASCII dependency tree
    #[arg(long = "no-tree", default_value_t = false)]
    no_tree: bool,

    /// Max depth for ASCII tree rendering
    #[arg(long = "tree-depth", default_value_t = 3)]
    tree_depth: usize,

    /// Show full dependency usage analysis (unused, dead imports, active)
    #[arg(long = "unused", default_value_t = false)]
    unused: bool,

    /// Suppress progress indicators
    #[arg(short = 'q', long = "quiet", default_value_t = false)]
    quiet: bool,

    /// Generate a .scala-dep-scan.yaml config with current findings pre-populated as ignored
    #[arg(long = "init", default_value_t = false)]
    init: bool,

    /// Auto-remove unused dependencies from build.sbt and lock.sbt (comments them out)
    #[arg(long = "fix-unused", default_value_t = false)]
    fix_unused: bool,

    /// Dry-run mode for --fix-unused: show what would be changed without modifying files
    #[arg(long = "dry-run", default_value_t = false)]
    dry_run: bool,

    /// Bypass the OSV response cache (~/.cache/scala-dep-scan/osv/)
    #[arg(long = "no-cache", default_value_t = false)]
    no_cache: bool,

    /// Generate SBOM in the given format (cyclonedx or spdx)
    #[arg(long = "sbom")]
    sbom: Option<String>,

    /// Output path for the SBOM file (default: stdout)
    #[arg(long = "sbom-output")]
    sbom_output: Option<PathBuf>,

    /// Generate an HTML dashboard report at the given path
    #[arg(long = "html")]
    html: Option<PathBuf>,

    /// Show license compliance information for all dependencies
    #[arg(long = "license", default_value_t = false)]
    license: bool,

    /// Enforce a license policy (e.g. "allow:MIT,Apache-2.0 deny:GPL-3.0")
    #[arg(long = "license-policy")]
    license_policy: Option<String>,

    /// Show dependency staleness report
    #[arg(long = "staleness", default_value_t = false)]
    staleness: bool,

    /// Show upgrade path recommendations
    #[arg(long = "upgrade-plan", default_value_t = false)]
    upgrade_plan: bool,

    /// Evaluate dependencies against a policy YAML file
    #[arg(long = "policy")]
    policy: Option<PathBuf>,

    /// Save current scan results as a baseline for future comparison
    #[arg(long = "save-baseline")]
    save_baseline: Option<PathBuf>,

    /// Compare current scan against a saved baseline file
    #[arg(long = "compare")]
    compare: Option<PathBuf>,

    /// Generate a CI configuration template (github or gitlab)
    #[arg(long = "generate-ci")]
    generate_ci: Option<String>,

    /// Launch interactive TUI explorer
    #[arg(long = "tui", default_value_t = false)]
    tui: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Handle --generate-ci early (no project scan needed)
    if let Some(ref platform) = cli.generate_ci {
        let template = ci_templates::generate_ci_template(platform);
        println!("{}", template);
        return Ok(());
    }

    let root = cli
        .path
        .canonicalize()
        .with_context(|| format!("Cannot access path: {}", cli.path.display()))?;

    let json_mode = cli.format == "json";

    // Load config early
    let cfg = config::Config::load(&root)?;

    // Use config severity threshold as default, CLI flag overrides
    let min_severity = if cli.min_severity != "low" {
        Severity::from_str(&cli.min_severity)
    } else {
        cfg.severity_threshold()
    };

    if !json_mode && !cli.tui {
        report::print_header();
    }

    // Step 1: Discover SBT files
    let pb = make_spinner(&cli, "Scanning project structure...");
    let project =
        parser::discover_sbt_files(&root).with_context(|| "Failed to scan project files")?;
    finish_spinner(
        &pb,
        &format!(
            "Found {} build.sbt + {} lock files{}",
            project.build_files.len(),
            project.lock_files.len(),
            if !project.modules.is_empty() {
                format!(" ({} modules)", project.modules.len())
            } else {
                String::new()
            }
        ),
    );

    if project.build_files.is_empty() {
        eprintln!(
            "{}",
            "No build.sbt files found. Is this a Scala/SBT project?".yellow()
        );
        std::process::exit(1);
    }

    // Step 2: Parse dependencies
    let pb = make_spinner(&cli, "Parsing dependency declarations...");
    let mut direct_deps: Vec<Dependency> = Vec::new();
    let mut transitive_deps: Vec<Dependency> = Vec::new();

    for path in &project.build_files {
        match parser::parse_build_sbt(path) {
            Ok(mut deps) => direct_deps.append(&mut deps),
            Err(e) => eprintln!("Could not parse {}: {}", path.display(), e),
        }
    }

    for path in &project.lock_files {
        match parser::parse_lock_file(path) {
            Ok(mut deps) => transitive_deps.append(&mut deps),
            Err(e) => eprintln!("Could not parse lockfile {}: {}", path.display(), e),
        }
    }

    dedup_deps(&mut direct_deps);
    dedup_deps(&mut transitive_deps);

    finish_spinner(
        &pb,
        &format!(
            "Parsed {} direct, {} transitive dependencies",
            direct_deps.len(),
            transitive_deps.len()
        ),
    );

    // Step 3: Risk analysis
    let pb = make_spinner(
        &cli,
        if cli.osv {
            "Running risk analysis + OSV advisory lookup..."
        } else {
            "Running risk analysis (use --osv for network lookup)..."
        },
    );

    let engine = risk::RiskEngine::new(cli.no_cache)?;
    let mut all_flags: Vec<RiskFlag> = Vec::new();
    let mut risk_map: HashMap<String, Severity> = HashMap::new();

    let all_deps: Vec<&Dependency> = direct_deps.iter().chain(transitive_deps.iter()).collect();

    for dep in &all_deps {
        let flags = engine.check(dep, cli.osv);
        for flag in &flags {
            let current = risk_map
                .get(&dep.coord())
                .cloned()
                .unwrap_or(Severity::Info);
            if flag.severity > current {
                risk_map.insert(dep.coord(), flag.severity.clone());
            }
        }
        all_flags.extend(flags);
    }

    // Deduplicate flags: same coord + same risk_type = keep worst
    all_flags.sort_by(|a, b| b.severity.cmp(&a.severity));
    let mut seen_flags = std::collections::HashSet::new();
    all_flags.retain(|f| {
        let key = format!("{}::{}", f.dependency.coord(), f.risk_type.label());
        seen_flags.insert(key)
    });

    finish_spinner(&pb, &format!("{} risk flags found", all_flags.len()));

    // Apply config ignore filtering
    let (all_flags, ignored_count) = cfg.filter_flags(all_flags);

    if ignored_count > 0 && !json_mode {
        println!(
            "  {} {} risk flags ignored via .scala-dep-scan.yaml",
            "ℹ".blue(),
            ignored_count
        );
    }

    // Handle --init: generate config and exit
    if cli.init {
        config::Config::generate_init(&root, &all_flags)?;
        if !json_mode {
            println!(
                "{}",
                "Generated .scala-dep-scan.yaml with current findings pre-populated."
                    .green()
                    .bold()
            );
            println!(
                "{}",
                "Edit the file to customize ignore rules and expiry dates.".dimmed()
            );
        }
        return Ok(());
    }

    // Step 4: Code reference scanning
    let pb = make_spinner(&cli, "Scanning Scala source files for import references...");
    let risky_dep_list: Vec<Dependency> = all_deps
        .iter()
        .filter(|d| risk_map.contains_key(&d.coord()))
        .map(|d| (*d).clone())
        .collect();

    let code_refs = scanner::scan_code_references(&root, &risky_dep_list).unwrap_or_default();

    let total_refs: usize = code_refs.values().map(|v| v.len()).sum();
    finish_spinner(
        &pb,
        &format!("{} code references found across risky deps", total_refs),
    );

    // Step 4b: Deep usage analysis (all deps — direct + transitive from lock.sbt)
    // Usage analysis always runs — dead weight detection is a core feature
    let usage_reports = {
        let pb = make_spinner(
            &cli,
            "Analysing symbol-level usage across all dependencies...",
        );
        let mut all_for_usage: Vec<Dependency> = direct_deps.clone();
        all_for_usage.extend(transitive_deps.clone());
        let reports = scanner::scan_usage(&root, &all_for_usage).unwrap_or_default();
        let unused_count = reports
            .iter()
            .filter(|r| r.verdict == UsageVerdict::Unused || r.verdict == UsageVerdict::DeadImport)
            .count();
        finish_spinner(
            &pb,
            &format!(
                "{} deps analysed -- {} unused or dead imports detected",
                reports.len(),
                unused_count
            ),
        );
        reports
    };

    // Step 4c: Classify transitive deps (orphan detection)
    let transitive_classifications = if !transitive_deps.is_empty() {
        let pb = make_spinner(&cli, "Classifying lock.sbt transitive dependencies...");
        let classifications =
            orphan::classify_transitive_deps(&direct_deps, &transitive_deps, &usage_reports);
        let orphaned_count = classifications.values().filter(|c| c.is_orphaned()).count();
        let linked_count = classifications
            .values()
            .filter(|c| matches!(c, types::TransitiveClassification::LinkedTo { .. }))
            .count();
        finish_spinner(
            &pb,
            &format!(
                "{} linked to active deps, {} likely orphaned",
                linked_count, orphaned_count
            ),
        );
        classifications
    } else {
        std::collections::HashMap::new()
    };

    // Handle --fix-unused
    if cli.fix_unused {
        let unused_reports: Vec<&types::DepUsageReport> = usage_reports
            .iter()
            .filter(|r| r.verdict == UsageVerdict::Unused)
            .collect();

        // Collect both build.sbt and lock.sbt files for removal
        let mut all_dep_files = project.build_files.clone();
        all_dep_files.extend(project.lock_files.clone());
        let results = rewriter::fix_unused(&root, &unused_reports, &all_dep_files, cli.dry_run)?;
        rewriter::print_rewrite_summary(&results, cli.dry_run);

        if !cli.dry_run && !results.is_empty() {
            // If we actually modified files, exit early with success
            return Ok(());
        }
    }

    // Step 5: Build dependency graph
    let pb = make_spinner(&cli, "Building dependency graph...");
    let graph = DepGraph::build_from_deps(&direct_deps, &transitive_deps, &risk_map);
    finish_spinner(&pb, "Dependency graph built");

    // ── Policy evaluation ────────────────────────────────────────────────
    if let Some(ref policy_path) = cli.policy {
        let pe = policy::PolicyEngine::load(policy_path.as_path())
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        if pe.policy_count() > 0 {
            let mut policy_violations = Vec::new();
            for dep in all_deps.iter() {
                let ctx = policy::DepContext {
                    org: dep.org.clone(),
                    name: dep.name.clone(),
                    version: dep.version.clone(),
                    coord: dep.coord(),
                    version_age_months: None,
                    license: String::new(),
                    is_direct: !dep.is_transitive,
                };
                policy_violations.extend(pe.evaluate(&ctx));
            }
            if !policy_violations.is_empty() && !json_mode {
                println!(
                    "\n{}",
                    "== Policy Violations ======================================================="
                        .cyan()
                );
                for v in &policy_violations {
                    println!(
                        "  [{:>8}] {} - {} (policy: {})",
                        v.severity.to_uppercase(),
                        v.coord,
                        v.reason,
                        v.policy_name
                    );
                }
                println!();
            }
        }
    }

    // ── License scanning ─────────────────────────────────────────────────
    if cli.license || cli.license_policy.is_some() {
        let license_deps: Vec<license::LicenseDep> = all_deps
            .iter()
            .map(|d| license::LicenseDep {
                org: d.org.clone(),
                name: d.name.clone(),
                version: d.version.clone(),
            })
            .collect();

        let cache_dir = dirs_cache_path("license");
        let mut cache = license::LicenseCache::new(Some(cache_dir));
        let license_results = license::scan_licenses(&license_deps, &mut cache);

        let mut violations = Vec::new();
        if let Some(ref policy_str) = cli.license_policy {
            let lp = license::LicensePolicy::from_str(policy_str);
            for info in &license_results {
                if let Some(v) = lp.check(info) {
                    violations.push(v);
                }
            }
        }

        if json_mode {
            println!(
                "{}",
                license::format_license_json(&license_results, &violations)
            );
        } else {
            print!(
                "{}",
                license::format_license_report(&license_results, &violations)
            );
        }
    }

    // ── Staleness report ─────────────────────────────────────────────────
    if cli.staleness {
        let staleness_deps: Vec<staleness::StalenessDep> = all_deps
            .iter()
            .map(|d| staleness::StalenessDep {
                org: d.org.clone(),
                name: d.name.clone(),
                version: d.version.clone(),
            })
            .collect();

        let staleness_reports = staleness::scan_staleness(&staleness_deps);

        if json_mode {
            println!("{}", staleness::format_staleness_json(&staleness_reports));
        } else {
            print!("{}", staleness::format_staleness_report(&staleness_reports));
        }
    }

    // ── Upgrade plan ─────────────────────────────────────────────────────
    if cli.upgrade_plan {
        let advisor_deps: Vec<advisor::AdvisorDep> = all_deps
            .iter()
            .map(|d| {
                let ref_count = code_refs.get(&d.coord()).map(|v| v.len()).unwrap_or(0);
                advisor::AdvisorDep {
                    org: d.org.clone(),
                    name: d.name.clone(),
                    version: d.version.clone(),
                    code_ref_count: ref_count,
                }
            })
            .collect();

        let ref_counts: HashMap<String, usize> = code_refs
            .iter()
            .map(|(k, v)| (k.clone(), v.len()))
            .collect();

        let recommendations = advisor::generate_upgrade_plan(&advisor_deps, &ref_counts);

        if json_mode {
            println!("{}", advisor::format_upgrade_json(&recommendations));
        } else {
            print!("{}", advisor::format_upgrade_plan(&recommendations));
        }
    }

    // ── SBOM generation ──────────────────────────────────────────────────
    if let Some(ref sbom_format_str) = cli.sbom {
        let sbom_fmt = sbom::SbomFormat::from_str(sbom_format_str).unwrap_or_else(|| {
            eprintln!(
                "{}",
                format!(
                    "Unknown SBOM format '{}'. Supported: cyclonedx, spdx",
                    sbom_format_str
                )
                .red()
            );
            std::process::exit(1);
        });

        let sbom_deps: Vec<sbom::SbomDependency> = all_deps
            .iter()
            .map(|d| sbom::SbomDependency {
                org: d.org.clone(),
                name: d.name.clone(),
                version: d.version.clone(),
                is_direct: !d.is_transitive,
                scope: d.scope.clone(),
            })
            .collect();

        let project_name = root
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "scala-project".to_string());

        let sbom_output =
            sbom::generate_sbom(sbom_fmt, &sbom_deps, &[], &HashMap::new(), &project_name);

        if let Some(ref out_path) = cli.sbom_output {
            fs::write(out_path, &sbom_output)
                .with_context(|| format!("Failed to write SBOM to {}", out_path.display()))?;
            if !json_mode {
                println!(
                    "{} {}",
                    "SBOM written to".green(),
                    out_path.display().to_string().yellow()
                );
            }
        } else {
            println!("{}", sbom_output);
        }
    }

    // ── Save baseline ────────────────────────────────────────────────────
    if let Some(ref baseline_path) = cli.save_baseline {
        let flags_json = serde_json::to_value(&all_flags).unwrap_or_default();
        diff::save_baseline(
            baseline_path.as_path(),
            &flags_json,
            direct_deps.len(),
            transitive_deps.len(),
        )
        .map_err(|e| anyhow::anyhow!("{}", e))?;
        if !json_mode {
            println!(
                "{} {}",
                "Baseline saved to".green(),
                baseline_path.display().to_string().yellow()
            );
        }
    }

    // ── Compare against baseline ─────────────────────────────────────────
    if let Some(ref compare_path) = cli.compare {
        let baseline =
            diff::load_baseline(compare_path.as_path()).map_err(|e| anyhow::anyhow!("{}", e))?;
        let current_flags_json = serde_json::to_value(&all_flags).unwrap_or_default();
        let diff_result = diff::compare(
            &baseline,
            &current_flags_json,
            direct_deps.len(),
            transitive_deps.len(),
        );

        if json_mode {
            println!("{}", diff::diff_to_json(&diff_result));
        } else {
            println!(
                "\n{}",
                "== Scan Comparison ========================================================="
                    .cyan()
            );
            println!("{}", diff_result.summary());
        }
    }

    // ── HTML report ──────────────────────────────────────────────────────
    if let Some(ref html_path) = cli.html {
        let graph_json_str = graph.to_json();
        let report_data = serde_json::json!({
            "direct_deps": &direct_deps,
            "transitive_deps": &transitive_deps,
            "risk_flags": &all_flags,
            "code_refs": &code_refs,
            "usage": &usage_reports,
            "graph_json": &graph_json_str,
        });
        let html_content = html_report::generate_html_report(&report_data);
        fs::write(html_path, &html_content)
            .with_context(|| format!("Failed to write HTML report to {}", html_path.display()))?;
        if !json_mode {
            println!(
                "{} {}",
                "HTML report written to".green(),
                html_path.display().to_string().yellow()
            );
        }
    }

    // ── TUI mode ─────────────────────────────────────────────────────────
    if cli.tui {
        let report_json = serde_json::json!({
            "summary": {
                "direct_deps": direct_deps.len(),
                "transitive_deps": transitive_deps.len(),
                "total_flags": all_flags.len(),
                "ignored_flags": ignored_count,
                "critical": all_flags.iter().filter(|f| f.severity == Severity::Critical).count(),
                "high": all_flags.iter().filter(|f| f.severity == Severity::High).count(),
                "medium": all_flags.iter().filter(|f| f.severity == Severity::Medium).count(),
                "low": all_flags.iter().filter(|f| f.severity == Severity::Low).count(),
            },
            "risk_flags": &all_flags,
            "dependency_usage": &usage_reports,
            "code_references": &code_refs,
            "graph": serde_json::from_str::<serde_json::Value>(&graph.to_json()).unwrap_or_default(),
        });
        let json_string =
            serde_json::to_string_pretty(&report_json).unwrap_or_else(|_| "{}".to_string());
        tui::run_tui(&json_string).map_err(|e| anyhow::anyhow!("{}", e))?;
        return Ok(());
    }

    // Step 6: Output
    if json_mode {
        report::print_json_report(
            &direct_deps,
            &transitive_deps,
            &all_flags,
            &code_refs,
            &graph,
            ignored_count,
            &usage_reports,
            &transitive_classifications,
        );
    } else {
        let private_count =
            report::count_private_deps(&direct_deps) + report::count_private_deps(&transitive_deps);
        report::print_summary(
            direct_deps.len(),
            transitive_deps.len(),
            &all_flags,
            &root.to_string_lossy(),
            ignored_count,
            private_count,
        );

        // Show multi-module info if detected
        if !project.modules.is_empty() {
            report::print_modules(&project.modules);
        }

        if cli.show_deps {
            report::print_dep_table(&direct_deps, "Direct Dependencies");
        }

        if !cli.no_tree {
            report::print_ascii_tree(&graph, &risk_map);
        }

        report::print_risk_flags(&all_flags, &code_refs, &min_severity);

        report::print_usage_report(&usage_reports, &transitive_classifications);

        report::print_legend();
    }

    if let Some(dot_path) = &cli.dot_output {
        let dot = graph.to_dot();
        fs::write(dot_path, dot)
            .with_context(|| format!("Failed to write DOT file to {}", dot_path.display()))?;
        if !json_mode {
            println!(
                "{} {}",
                "DOT graph written to".green(),
                dot_path.display().to_string().yellow()
            );
        }
    }

    if let Some(json_path) = &cli.graph_json_output {
        let json = graph.to_json();
        fs::write(json_path, json)
            .with_context(|| format!("Failed to write JSON graph to {}", json_path.display()))?;
        if !json_mode {
            println!(
                "{} {}",
                "JSON graph written to".green(),
                json_path.display().to_string().yellow()
            );
        }
    }

    let has_critical = all_flags.iter().any(|f| f.severity == Severity::Critical);
    let has_high = all_flags.iter().any(|f| f.severity == Severity::High);
    if has_critical {
        std::process::exit(2);
    } else if has_high {
        std::process::exit(1);
    }

    Ok(())
}

/// Helper to get a cache directory path under ~/.cache/scala-dep-scan/
fn dirs_cache_path(subdir: &str) -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    format!("{}/.cache/scala-dep-scan/{}", home, subdir)
}

fn dedup_deps(deps: &mut Vec<Dependency>) {
    let mut seen = std::collections::HashSet::new();
    deps.retain(|d| {
        // Normalize dep name by stripping Scala version suffix before comparing,
        // so that e.g. "play-slick" and "play-slick_2.11" are treated as duplicates.
        let normalized_name = parser::strip_scala_suffix(&d.name);
        let key = format!("{}:{}", d.org, normalized_name);
        seen.insert(key)
    });
}

fn make_spinner(cli: &Cli, msg: &str) -> ProgressBar {
    if cli.quiet || cli.format == "json" {
        return ProgressBar::hidden();
    }
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

fn finish_spinner(pb: &ProgressBar, msg: &str) {
    pb.finish_with_message(format!("{} {}", "✓".green(), msg));
}
