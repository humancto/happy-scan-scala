use anyhow::Result;
use regex::Regex;
use std::fs;
use std::path::Path;

use crate::types::DepUsageReport;

/// Result of a rewrite operation on a single build.sbt file
#[derive(Debug)]
pub struct RewriteResult {
    pub file_path: String,
    pub removed: Vec<RewriteEntry>,
    pub backup_path: Option<String>,
}

#[derive(Debug)]
pub struct RewriteEntry {
    pub line_number: usize,
    pub original_line: String,
    pub coord: String,
}

/// Fix unused dependencies in build.sbt files found under the project root.
/// If `dry_run` is true, only prints what would be changed.
/// Returns a list of rewrite results.
pub fn fix_unused(
    _project_root: &Path,
    unused_reports: &[&DepUsageReport],
    build_files: &[std::path::PathBuf],
    dry_run: bool,
) -> Result<Vec<RewriteResult>> {
    let mut results = Vec::new();

    // Build a set of coords to remove
    let unused_coords: std::collections::HashSet<String> =
        unused_reports.iter().map(|r| r.coord.clone()).collect();

    if unused_coords.is_empty() {
        return Ok(results);
    }

    // Regex to match SBT dependency lines and extract org:name
    let dep_re =
        Regex::new(r#"["']([^"']+)["']\s*(%{1,2})\s*["']([^"']+)["']\s*%\s*["']([^"']+)["']"#)?;
    let dep_var_re =
        Regex::new(r#"["']([^"']+)["']\s*(%{1,2})\s*["']([^"']+)["']\s*%\s*([a-zA-Z]\w+)"#)?;

    for build_file in build_files {
        let content = fs::read_to_string(build_file)?;
        let lines: Vec<&str> = content.lines().collect();
        let mut new_lines: Vec<String> = Vec::with_capacity(lines.len());
        let mut removed_entries: Vec<RewriteEntry> = Vec::new();

        for (i, line) in lines.iter().enumerate() {
            let mut should_comment = false;
            let mut matched_coord = String::new();

            // Try standard dep pattern
            if let Some(cap) = dep_re.captures(line) {
                let org = &cap[1];
                let name = &cap[3];
                let coord = format!("{}:{}", org, name);
                if unused_coords.contains(&coord) {
                    should_comment = true;
                    matched_coord = coord;
                }
            }

            // Try variable-version dep pattern
            if !should_comment {
                if let Some(cap) = dep_var_re.captures(line) {
                    let org = &cap[1];
                    let name = &cap[3];
                    let coord = format!("{}:{}", org, name);
                    if unused_coords.contains(&coord) {
                        should_comment = true;
                        matched_coord = coord;
                    }
                }
            }

            if should_comment {
                removed_entries.push(RewriteEntry {
                    line_number: i + 1,
                    original_line: line.to_string(),
                    coord: matched_coord,
                });
                new_lines.push(format!("// REMOVED by scala-dep-scan: {}", line));
            } else {
                new_lines.push(line.to_string());
            }
        }

        if removed_entries.is_empty() {
            continue;
        }

        let backup_path = if !dry_run {
            // Create backup
            let bak = format!("{}.bak", build_file.display());
            fs::copy(build_file, &bak)?;
            // Write modified file
            let new_content = new_lines.join("\n");
            // Preserve trailing newline if original had one
            let new_content = if content.ends_with('\n') {
                format!("{}\n", new_content)
            } else {
                new_content
            };
            fs::write(build_file, new_content)?;
            Some(bak)
        } else {
            None
        };

        results.push(RewriteResult {
            file_path: build_file.to_string_lossy().to_string(),
            removed: removed_entries,
            backup_path,
        });
    }

    Ok(results)
}

/// Print a diff-style summary of the rewrite results.
pub fn print_rewrite_summary(results: &[RewriteResult], dry_run: bool) {
    use colored::*;

    if results.is_empty() {
        println!(
            "{}",
            "No unused dependencies found in build.sbt/lock.sbt files to remove.".dimmed()
        );
        return;
    }

    if dry_run {
        println!(
            "{}",
            "── Dry Run: Proposed Changes ──────────────────────────────"
                .yellow()
                .bold()
        );
    } else {
        println!(
            "{}",
            "── Applied Changes ────────────────────────────────────────"
                .green()
                .bold()
        );
    }
    println!();

    for result in results {
        println!("  {} {}", "File:".bold(), result.file_path.cyan());
        if let Some(bak) = &result.backup_path {
            println!("  {} {}", "Backup:".dimmed(), bak.dimmed());
        }
        println!();

        for entry in &result.removed {
            println!(
                "  {} L{}: {}",
                "-".red().bold(),
                entry.line_number.to_string().dimmed(),
                entry.original_line.trim().red()
            );
            println!(
                "  {} L{}: {}{}",
                "+".green().bold(),
                entry.line_number.to_string().dimmed(),
                "// REMOVED by scala-dep-scan: ".green(),
                entry.original_line.trim().green()
            );
            println!("    {} {}", "coord:".dimmed(), entry.coord.yellow());
            println!();
        }
    }

    let total: usize = results.iter().map(|r| r.removed.len()).sum();
    if dry_run {
        println!(
            "  {} {} dependencies would be commented out. Use without --dry-run to apply.",
            "Summary:".bold(),
            total.to_string().yellow().bold()
        );
    } else {
        println!(
            "  {} {} dependencies commented out.",
            "Summary:".bold(),
            total.to_string().green().bold()
        );
    }
    println!();
}
