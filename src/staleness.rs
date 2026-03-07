// Dependency staleness scoring module
// Queries Maven Central for latest version info and calculates staleness metrics.
// Self-contained — uses curl subprocess (same pattern as risk.rs).

use serde::{Deserialize, Serialize};

/// Age category for color-coded display
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AgeCategory {
    /// < 6 months — green
    Current,
    /// 6-18 months — yellow
    Aging,
    /// 18-36 months — orange
    Stale,
    /// > 36 months — red
    Outdated,
    /// Could not determine
    Unknown,
}

impl AgeCategory {
    pub fn label(&self) -> &str {
        match self {
            AgeCategory::Current => "CURRENT",
            AgeCategory::Aging => "AGING",
            AgeCategory::Stale => "STALE",
            AgeCategory::Outdated => "OUTDATED",
            AgeCategory::Unknown => "UNKNOWN",
        }
    }

    pub fn color_code(&self) -> &str {
        match self {
            AgeCategory::Current => "green",
            AgeCategory::Aging => "yellow",
            AgeCategory::Stale => "orange",
            AgeCategory::Outdated => "red",
            AgeCategory::Unknown => "dimmed",
        }
    }
}

/// Staleness report for a single dependency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StalenessReport {
    pub coord: String,
    pub current_version: String,
    pub latest_version: String,
    pub versions_behind: u32,
    pub age_months: Option<u32>,
    pub age_category: AgeCategory,
    pub update_available: bool,
}

/// Minimal dependency info for staleness scanning
#[derive(Debug, Clone)]
pub struct StalenessDep {
    pub org: String,
    pub name: String,
    pub version: String,
}

impl StalenessDep {
    pub fn coord(&self) -> String {
        format!("{}:{}", self.org, self.name)
    }
}

/// Scan staleness for a list of dependencies
pub fn scan_staleness(deps: &[StalenessDep]) -> Vec<StalenessReport> {
    let mut reports: Vec<StalenessReport> = Vec::new();

    for dep in deps {
        let report = check_staleness(dep);
        reports.push(report);
    }

    // Sort: most outdated first
    reports.sort_by(|a, b| {
        let cat_ord = |c: &AgeCategory| -> u8 {
            match c {
                AgeCategory::Outdated => 0,
                AgeCategory::Stale => 1,
                AgeCategory::Aging => 2,
                AgeCategory::Current => 3,
                AgeCategory::Unknown => 4,
            }
        };
        cat_ord(&a.age_category)
            .cmp(&cat_ord(&b.age_category))
            .then(b.versions_behind.cmp(&a.versions_behind))
    });

    reports
}

/// Check staleness for a single dependency via Maven Central
fn check_staleness(dep: &StalenessDep) -> StalenessReport {
    let url = format!(
        "https://search.maven.org/solrsearch/select?q=g:\"{}\"%%20AND%%20a:\"{}\"&rows=1&core=gav&wt=json",
        dep.org, dep.name
    );

    let output = std::process::Command::new("curl")
        .args(["-s", "--max-time", "5", &url])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let body = String::from_utf8_lossy(&out.stdout);
            parse_staleness_response(&body, dep)
        }
        _ => StalenessReport {
            coord: dep.coord(),
            current_version: dep.version.clone(),
            latest_version: "unknown".to_string(),
            versions_behind: 0,
            age_months: None,
            age_category: AgeCategory::Unknown,
            update_available: false,
        },
    }
}

/// Parse Maven Central GAV response
fn parse_staleness_response(body: &str, dep: &StalenessDep) -> StalenessReport {
    let default = StalenessReport {
        coord: dep.coord(),
        current_version: dep.version.clone(),
        latest_version: "unknown".to_string(),
        versions_behind: 0,
        age_months: None,
        age_category: AgeCategory::Unknown,
        update_available: false,
    };

    let parsed: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return default,
    };

    let docs = match parsed["response"]["docs"].as_array() {
        Some(d) if !d.is_empty() => d,
        _ => {
            // Try non-GAV search as fallback
            return check_staleness_fallback(dep);
        }
    };

    let doc = &docs[0];

    let latest_version = doc["v"]
        .as_str()
        .or_else(|| doc["latestVersion"].as_str())
        .unwrap_or("unknown")
        .to_string();

    let timestamp_ms = doc["timestamp"].as_i64().unwrap_or(0);

    let age_months = if timestamp_ms > 0 {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let diff_ms = now_ms - timestamp_ms;
        let months = (diff_ms as f64 / (30.44 * 24.0 * 3600.0 * 1000.0)) as u32;
        Some(months)
    } else {
        None
    };

    let age_category = match age_months {
        Some(m) if m < 6 => AgeCategory::Current,
        Some(m) if m < 18 => AgeCategory::Aging,
        Some(m) if m < 36 => AgeCategory::Stale,
        Some(_) => AgeCategory::Outdated,
        None => AgeCategory::Unknown,
    };

    let versions_behind = estimate_versions_behind(&dep.version, &latest_version);
    let update_available = latest_version != "unknown" && latest_version != dep.version;

    StalenessReport {
        coord: dep.coord(),
        current_version: dep.version.clone(),
        latest_version,
        versions_behind,
        age_months,
        age_category,
        update_available,
    }
}

/// Fallback staleness check using non-GAV Maven search
fn check_staleness_fallback(dep: &StalenessDep) -> StalenessReport {
    let url = format!(
        "https://search.maven.org/solrsearch/select?q=g:\"{}\"%%20AND%%20a:\"{}\"&rows=1&wt=json",
        dep.org, dep.name
    );

    let output = std::process::Command::new("curl")
        .args(["-s", "--max-time", "5", &url])
        .output();

    let default = StalenessReport {
        coord: dep.coord(),
        current_version: dep.version.clone(),
        latest_version: "unknown".to_string(),
        versions_behind: 0,
        age_months: None,
        age_category: AgeCategory::Unknown,
        update_available: false,
    };

    match output {
        Ok(out) if out.status.success() => {
            let body = String::from_utf8_lossy(&out.stdout);
            let parsed: serde_json::Value = match serde_json::from_str(&*body) {
                Ok(v) => v,
                Err(_) => return default,
            };

            let docs = match parsed["response"]["docs"].as_array() {
                Some(d) if !d.is_empty() => d,
                _ => return default,
            };

            let doc = &docs[0];
            let latest_version = doc["latestVersion"]
                .as_str()
                .unwrap_or("unknown")
                .to_string();

            let timestamp_ms = doc["timestamp"].as_i64().unwrap_or(0);

            let age_months = if timestamp_ms > 0 {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64;
                let diff_ms = now_ms - timestamp_ms;
                let months = (diff_ms as f64 / (30.44 * 24.0 * 3600.0 * 1000.0)) as u32;
                Some(months)
            } else {
                None
            };

            let age_category = match age_months {
                Some(m) if m < 6 => AgeCategory::Current,
                Some(m) if m < 18 => AgeCategory::Aging,
                Some(m) if m < 36 => AgeCategory::Stale,
                Some(_) => AgeCategory::Outdated,
                None => AgeCategory::Unknown,
            };

            let versions_behind = estimate_versions_behind(&dep.version, &latest_version);
            let update_available = latest_version != "unknown" && latest_version != dep.version;

            StalenessReport {
                coord: dep.coord(),
                current_version: dep.version.clone(),
                latest_version,
                versions_behind,
                age_months,
                age_category,
                update_available,
            }
        }
        _ => default,
    }
}

/// Estimate how many major+minor versions behind the current version is
fn estimate_versions_behind(current: &str, latest: &str) -> u32 {
    let cur_parts = parse_version_parts(current);
    let lat_parts = parse_version_parts(latest);

    match (cur_parts, lat_parts) {
        (Some((cmaj, cmin, cpatch)), Some((lmaj, lmin, lpatch))) => {
            if lmaj > cmaj {
                // Major version difference
                let major_diff = lmaj - cmaj;
                // Estimate: each major = ~10 minor versions
                major_diff * 10 + lmin
            } else if lmin > cmin {
                let minor_diff = lmin - cmin;
                minor_diff + if lpatch > cpatch { 1 } else { 0 }
            } else if lpatch > cpatch {
                lpatch - cpatch
            } else {
                0
            }
        }
        _ => 0,
    }
}

/// Parse version string into (major, minor, patch) tuple
fn parse_version_parts(v: &str) -> Option<(u32, u32, u32)> {
    let cleaned = v.split('-').next().unwrap_or(v);
    let cleaned = cleaned.split('+').next().unwrap_or(cleaned);
    let parts: Vec<&str> = cleaned.split('.').collect();

    match parts.len() {
        1 => {
            let major = parts[0].parse().ok()?;
            Some((major, 0, 0))
        }
        2 => {
            let major = parts[0].parse().ok()?;
            let minor = parts[1].parse().ok()?;
            Some((major, minor, 0))
        }
        _ => {
            let major = parts[0].parse().ok()?;
            let minor = parts[1].parse().ok()?;
            let patch = parts[2].parse().ok()?;
            Some((major, minor, patch))
        }
    }
}

/// Format staleness report for terminal output
pub fn format_staleness_report(reports: &[StalenessReport]) -> String {
    let mut out = String::new();

    out.push_str(
        "== Dependency Staleness Report ==============================================\n\n",
    );

    let current = reports
        .iter()
        .filter(|r| r.age_category == AgeCategory::Current)
        .count();
    let aging = reports
        .iter()
        .filter(|r| r.age_category == AgeCategory::Aging)
        .count();
    let stale = reports
        .iter()
        .filter(|r| r.age_category == AgeCategory::Stale)
        .count();
    let outdated = reports
        .iter()
        .filter(|r| r.age_category == AgeCategory::Outdated)
        .count();
    let unknown = reports
        .iter()
        .filter(|r| r.age_category == AgeCategory::Unknown)
        .count();
    let updatable = reports.iter().filter(|r| r.update_available).count();

    out.push_str(&format!(
        "  {} Current (<6mo)  |  {} Aging (6-18mo)  |  {} Stale (18-36mo)  |  {} Outdated (>36mo)  |  {} Unknown\n",
        current, aging, stale, outdated, unknown
    ));
    out.push_str(&format!(
        "  {} dependencies have updates available\n\n",
        updatable
    ));

    // Table header
    out.push_str(&format!(
        "  {:<45} {:<15} {:<15} {:<8} {:<10}\n",
        "DEPENDENCY", "CURRENT", "LATEST", "BEHIND", "STATUS"
    ));
    out.push_str(&format!("  {}\n", "-".repeat(95)));

    for report in reports {
        let status_marker = match report.age_category {
            AgeCategory::Current => "[OK]",
            AgeCategory::Aging => "[!!]",
            AgeCategory::Stale => "[##]",
            AgeCategory::Outdated => "[XX]",
            AgeCategory::Unknown => "[??]",
        };

        let age_str = match report.age_months {
            Some(m) => format!("{}mo", m),
            None => "?".to_string(),
        };

        let behind_str = if report.versions_behind > 0 {
            format!("~{}", report.versions_behind)
        } else {
            "-".to_string()
        };

        out.push_str(&format!(
            "  {:<45} {:<15} {:<15} {:<8} {} {} ({})\n",
            truncate_str(&report.coord, 44),
            truncate_str(&report.current_version, 14),
            truncate_str(&report.latest_version, 14),
            behind_str,
            status_marker,
            report.age_category.label(),
            age_str,
        ));
    }

    out.push('\n');
    out
}

/// Format staleness report as JSON
pub fn format_staleness_json(reports: &[StalenessReport]) -> String {
    let report = serde_json::json!({
        "staleness": reports,
        "summary": {
            "total": reports.len(),
            "current": reports.iter().filter(|r| r.age_category == AgeCategory::Current).count(),
            "aging": reports.iter().filter(|r| r.age_category == AgeCategory::Aging).count(),
            "stale": reports.iter().filter(|r| r.age_category == AgeCategory::Stale).count(),
            "outdated": reports.iter().filter(|r| r.age_category == AgeCategory::Outdated).count(),
            "unknown": reports.iter().filter(|r| r.age_category == AgeCategory::Unknown).count(),
            "updates_available": reports.iter().filter(|r| r.update_available).count(),
        }
    });
    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max - 3])
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parts() {
        assert_eq!(parse_version_parts("2.13.10"), Some((2, 13, 10)));
        assert_eq!(parse_version_parts("1.0"), Some((1, 0, 0)));
        assert_eq!(parse_version_parts("3.0.0-RC1"), Some((3, 0, 0)));
    }

    #[test]
    fn test_versions_behind() {
        assert_eq!(estimate_versions_behind("2.12.0", "2.13.10"), 11);
        assert_eq!(estimate_versions_behind("1.0.0", "2.0.0"), 10);
        assert_eq!(estimate_versions_behind("2.9.0", "2.9.4"), 4);
    }

    #[test]
    fn test_age_category() {
        let report = StalenessReport {
            coord: "org:lib".to_string(),
            current_version: "1.0.0".to_string(),
            latest_version: "2.0.0".to_string(),
            versions_behind: 10,
            age_months: Some(40),
            age_category: AgeCategory::Outdated,
            update_available: true,
        };
        assert_eq!(report.age_category.label(), "OUTDATED");
    }
}
