use crate::types::{Dependency, ParsedProject, SbtModule};
use anyhow::Result;
use regex::Regex;
use std::fs;
use std::path::Path;

/// Parses build.sbt files, handling various SBT dependency declaration styles
pub fn parse_build_sbt(path: &Path) -> Result<Vec<Dependency>> {
    let content = fs::read_to_string(path)?;
    let mut deps = Vec::new();

    // Match various SBT dependency styles:
    // "org" % "name" % "version"
    // "org" %% "name" % "version"  (Scala cross-compiled)
    // ("org" % "name" % "version" % "scope")
    let re_standard = Regex::new(
        r#"["']([^"']+)["']\s*(%{1,2})\s*["']([^"']+)["']\s*%\s*["']([^"']+)["'](?:\s*%\s*["']([^"']+)["'])?"#,
    )?;

    // val / lazy val version aliases: val akkaVersion = "2.6.19"
    let re_val = Regex::new(r#"(?:lazy\s+)?val\s+(\w+)\s*=\s*["']([0-9][^"']+)["']"#)?;

    // Collect version variables first
    let mut version_vars: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for cap in re_val.captures_iter(&content) {
        version_vars.insert(cap[1].to_string(), cap[2].to_string());
    }

    // Match deps that use variable versions: "org" % "name" % akkaVersion
    let re_varver =
        Regex::new(r#"["']([^"']+)["']\s*(%{1,2})\s*["']([^"']+)["']\s*%\s*([a-zA-Z]\w+)"#)?;

    for cap in re_standard.captures_iter(&content) {
        let org = cap[1].to_string();
        let cross = &cap[2] == "%%";
        let name = cap[3].to_string();
        let version = cap[4].to_string();
        let scope = cap.get(5).map(|m| m.as_str().to_string());

        deps.push(Dependency {
            org: org.clone(),
            name: name.clone(),
            version: version.clone(),
            scope,
            cross_compiled: cross,
            source_file: path.to_string_lossy().to_string(),
            is_transitive: false,
        });
    }

    // Match variable-referenced versions
    for cap in re_varver.captures_iter(&content) {
        let org = cap[1].to_string();
        let cross = &cap[2] == "%%";
        let name = cap[3].to_string();
        let var_name = &cap[4];

        if let Some(version) = version_vars.get(var_name) {
            // Avoid duplicates already caught by standard regex
            let already_found = deps.iter().any(|d| d.org == org && d.name == name);
            if !already_found {
                deps.push(Dependency {
                    org: org.clone(),
                    name: name.clone(),
                    version: version.clone(),
                    scope: None,
                    cross_compiled: cross,
                    source_file: path.to_string_lossy().to_string(),
                    is_transitive: false,
                });
            }
        }
    }

    Ok(deps)
}

/// Parses build.sbt.lock (Coursier lockfile format)
pub fn parse_lock_file(path: &Path) -> Result<Vec<Dependency>> {
    let content = fs::read_to_string(path)?;
    let mut deps = Vec::new();

    // Coursier lockfile format:
    // [dependencies]
    // com.typesafe.play:play_2.13:2.8.19
    // org.apache.commons:commons-collections:3.2.1
    let re_dep = Regex::new(r"^([a-zA-Z0-9_.\-]+):([a-zA-Z0-9_.\-]+(?:_2\.\d+)?):([0-9][^\s#]+)")?;

    let mut in_deps = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "[dependencies]" {
            in_deps = true;
            continue;
        }
        if trimmed.starts_with('[') {
            in_deps = false;
        }

        if in_deps && !trimmed.is_empty() && !trimmed.starts_with('#') {
            if let Some(cap) = re_dep.captures(trimmed) {
                let full_name = cap[2].to_string();
                // Strip scala version suffix for cleaner matching
                let name = strip_scala_suffix(&full_name);

                deps.push(Dependency {
                    org: cap[1].to_string(),
                    name,
                    version: cap[3].trim().to_string(),
                    scope: None,
                    cross_compiled: full_name.contains("_2."),
                    source_file: path.to_string_lossy().to_string(),
                    is_transitive: true,
                });
            }
        }
    }

    // Also handle flat lockfile style (one dep per line, no sections)
    if deps.is_empty() {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('[') {
                continue;
            }
            if let Some(cap) = re_dep.captures(trimmed) {
                let full_name = cap[2].to_string();
                let name = strip_scala_suffix(&full_name);
                deps.push(Dependency {
                    org: cap[1].to_string(),
                    name,
                    version: cap[3].trim().to_string(),
                    scope: None,
                    cross_compiled: full_name.contains("_2."),
                    source_file: path.to_string_lossy().to_string(),
                    is_transitive: true,
                });
            }
        }
    }

    Ok(deps)
}

/// Discovers all build.sbt and build.sbt.lock files in a project
pub fn discover_sbt_files(root: &Path) -> Result<ParsedProject> {
    let mut project = ParsedProject {
        root: root.to_path_buf(),
        build_files: vec![],
        lock_files: vec![],
        modules: vec![],
    };

    let mut build_scala_files: Vec<std::path::PathBuf> = vec![];

    for entry in walkdir::WalkDir::new(root)
        .max_depth(4)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let fname = entry.file_name().to_string_lossy().to_string();
        let path = entry.path().to_path_buf();

        // Skip target/ and .git/ directories
        if path.components().any(|c| {
            let s = c.as_os_str().to_string_lossy();
            s == "target" || s == ".git" || s == ".metals" || s == ".bsp"
        }) {
            continue;
        }

        if fname == "build.sbt" {
            project.build_files.push(path);
        } else if fname.ends_with(".sbt.lock") || fname == "build.sbt.lock" {
            project.lock_files.push(path.clone());
        } else if fname == "Build.scala" {
            build_scala_files.push(path);
        }
    }

    // Parse multi-module definitions from build.sbt files
    for build_file in &project.build_files {
        if let Ok(modules) = parse_multi_module_build(build_file) {
            project.modules.extend(modules);
        }
    }

    // Parse Build.scala files
    for build_scala in &build_scala_files {
        if let Ok(modules) = parse_build_scala(build_scala) {
            project.modules.extend(modules);
        }
    }

    Ok(project)
}

/// Parse multi-project build definitions from a build.sbt file.
/// Detects patterns like: lazy val subproject = (project in file("sub"))
pub fn parse_multi_module_build(path: &Path) -> Result<Vec<SbtModule>> {
    let content = fs::read_to_string(path)?;
    let mut modules = Vec::new();

    // Match: lazy val name = (project in file("path"))
    let re_project = Regex::new(
        r#"(?:lazy\s+)?val\s+(\w+)\s*=\s*\(?project\s+in\s+file\(\s*["']([^"']+)["']\s*\)\)?"#,
    )?;

    // Match: lazy val name = project
    let re_project_simple = Regex::new(r#"(?:lazy\s+)?val\s+(\w+)\s*=\s*project\b"#)?;

    // Match: .dependsOn(a, b, c)
    let re_depends_on = Regex::new(r#"\.dependsOn\(([^)]+)\)"#)?;

    // Match: .aggregate(a, b, c)
    let re_aggregate = Regex::new(r#"\.aggregate\(([^)]+)\)"#)?;

    // First pass: find all project definitions
    let mut project_defs: Vec<(String, String, usize)> = Vec::new(); // (name, path, line_index)

    let lines: Vec<&str> = content.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        if let Some(cap) = re_project.captures(line) {
            project_defs.push((cap[1].to_string(), cap[2].to_string(), i));
        } else if let Some(cap) = re_project_simple.captures(line) {
            let name = cap[1].to_string();
            project_defs.push((name.clone(), name.clone(), i));
        }
    }

    // Second pass: for each project, look for .dependsOn and .aggregate in nearby lines
    for (name, proj_path, line_idx) in &project_defs {
        let mut depends_on = Vec::new();
        let mut aggregates = Vec::new();

        // Scan from the project definition line through the next few lines
        // (SBT definitions can span multiple lines with method chaining)
        let start = *line_idx;
        let end = (start + 10).min(lines.len());
        let block = lines[start..end].join("\n");

        for cap in re_depends_on.captures_iter(&block) {
            let deps_str = &cap[1];
            for dep in deps_str.split(',') {
                let dep = dep.trim();
                if !dep.is_empty() {
                    depends_on.push(dep.to_string());
                }
            }
        }

        for cap in re_aggregate.captures_iter(&block) {
            let agg_str = &cap[1];
            for agg in agg_str.split(',') {
                let agg = agg.trim();
                if !agg.is_empty() {
                    aggregates.push(agg.to_string());
                }
            }
        }

        // Parse deps from lines within the module's settings block
        let module_deps = Vec::new(); // deps will be populated from the main parser

        modules.push(SbtModule {
            name: name.clone(),
            path: proj_path.clone(),
            deps: module_deps,
            depends_on,
            aggregates,
        });
    }

    Ok(modules)
}

/// Parse project/Build.scala files for multi-module definitions
pub fn parse_build_scala(path: &Path) -> Result<Vec<SbtModule>> {
    let content = fs::read_to_string(path)?;
    let mut modules = Vec::new();

    // Match: lazy val name = Project("name", file("path"))
    let re_project = Regex::new(
        r#"(?:lazy\s+)?val\s+(\w+)\s*=\s*Project\(\s*["']([^"']+)["']\s*,\s*file\(\s*["']([^"']+)["']\s*\)"#,
    )?;

    // Match: lazy val name = (project in file("path")) - same as build.sbt
    let re_project_in = Regex::new(
        r#"(?:lazy\s+)?val\s+(\w+)\s*=\s*\(?project\s+in\s+file\(\s*["']([^"']+)["']\s*\)\)?"#,
    )?;

    let re_depends_on = Regex::new(r#"\.dependsOn\(([^)]+)\)"#)?;
    let re_aggregate = Regex::new(r#"\.aggregate\(([^)]+)\)"#)?;

    let lines: Vec<&str> = content.lines().collect();
    let mut project_defs: Vec<(String, String, usize)> = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        if let Some(cap) = re_project.captures(line) {
            project_defs.push((cap[1].to_string(), cap[3].to_string(), i));
        } else if let Some(cap) = re_project_in.captures(line) {
            project_defs.push((cap[1].to_string(), cap[2].to_string(), i));
        }
    }

    for (name, proj_path, line_idx) in &project_defs {
        let mut depends_on = Vec::new();
        let mut aggregates = Vec::new();

        let start = *line_idx;
        let end = (start + 15).min(lines.len());
        let block = lines[start..end].join("\n");

        for cap in re_depends_on.captures_iter(&block) {
            for dep in cap[1].split(',') {
                let dep = dep.trim();
                if !dep.is_empty() {
                    depends_on.push(dep.to_string());
                }
            }
        }

        for cap in re_aggregate.captures_iter(&block) {
            for agg in cap[1].split(',') {
                let agg = agg.trim();
                if !agg.is_empty() {
                    aggregates.push(agg.to_string());
                }
            }
        }

        // Parse dependencies from Build.scala
        let deps = parse_build_sbt(path).unwrap_or_default();

        modules.push(SbtModule {
            name: name.clone(),
            path: proj_path.clone(),
            deps,
            depends_on,
            aggregates,
        });
    }

    Ok(modules)
}

fn strip_scala_suffix(name: &str) -> String {
    // Remove _2.12, _2.13, _3 etc.
    let re = Regex::new(r"_2\.\d+$|_3$").unwrap();
    re.replace(name, "").to_string()
}
