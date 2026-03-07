mod config;
mod graph;
mod parser;
mod report;
mod rewriter;
mod risk;
mod scanner;
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
    long_about = "Scans build.sbt and *.sbt.lock files to identify risky dependencies,\nbuild a dependency graph, and locate related code in your project.",
    version = "0.2.0"
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

    /// Auto-remove unused dependencies from build.sbt (comments them out)
    #[arg(long = "fix-unused", default_value_t = false)]
    fix_unused: bool,

    /// Dry-run mode for --fix-unused: show what would be changed without modifying files
    #[arg(long = "dry-run", default_value_t = false)]
    dry_run: bool,

    /// Bypass the OSV response cache (~/.cache/scala-dep-scan/osv/)
    #[arg(long = "no-cache", default_value_t = false)]
    no_cache: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

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

    if !json_mode {
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

    // Step 4b: Deep usage analysis (all direct deps)
    let usage_reports = if cli.unused || cli.fix_unused || !json_mode {
        let pb = make_spinner(
            &cli,
            "Analysing symbol-level usage across all dependencies...",
        );
        let all_direct: Vec<Dependency> = direct_deps.clone();
        let reports = scanner::scan_usage(&root, &all_direct).unwrap_or_default();
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
    } else {
        vec![]
    };

    // Handle --fix-unused
    if cli.fix_unused {
        let unused_reports: Vec<&types::DepUsageReport> = usage_reports
            .iter()
            .filter(|r| r.verdict == UsageVerdict::Unused)
            .collect();

        let results =
            rewriter::fix_unused(&root, &unused_reports, &project.build_files, cli.dry_run)?;
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

    // Step 6: Output
    if json_mode {
        report::print_json_report(
            &direct_deps,
            &transitive_deps,
            &all_flags,
            &code_refs,
            &graph,
            ignored_count,
        );
    } else {
        report::print_summary(
            direct_deps.len(),
            transitive_deps.len(),
            &all_flags,
            &root.to_string_lossy(),
            ignored_count,
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

        report::print_usage_report(&usage_reports);

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

fn dedup_deps(deps: &mut Vec<Dependency>) {
    let mut seen = std::collections::HashSet::new();
    deps.retain(|d| seen.insert(d.coord()));
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
