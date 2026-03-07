use crate::types::{Dependency, OsvResponse, RiskFlag, RiskType, RiskyDepEntry, Severity};
use anyhow::Result;
use semver::Version;
use std::fs;
use std::path::PathBuf;

const RISKY_DEPS_JSON: &str = include_str!("../data/risky_deps.json");
/// Cache TTL: 24 hours in seconds
const CACHE_TTL_SECS: u64 = 24 * 60 * 60;

pub struct RiskEngine {
    known_bad: Vec<RiskyDepEntry>,
    no_cache: bool,
}

impl RiskEngine {
    pub fn new(no_cache: bool) -> Result<Self> {
        let known_bad: Vec<RiskyDepEntry> = serde_json::from_str(RISKY_DEPS_JSON)?;
        Ok(Self {
            known_bad,
            no_cache,
        })
    }

    /// Run all risk checks on a dependency
    pub fn check(&self, dep: &Dependency, run_osv: bool) -> Vec<RiskFlag> {
        let mut flags = Vec::new();

        // 1. Check against known-bad database
        if let Some(flag) = self.check_known_bad(dep) {
            flags.push(flag);
        }

        // 2. Check for staleness heuristics
        if let Some(flag) = self.check_staleness(dep) {
            flags.push(flag);
        }

        // 3. OSV/NVD API lookup (if enabled)
        if run_osv {
            if let Ok(osv_flags) = self.check_osv(dep) {
                flags.extend(osv_flags);
            }
        }

        flags
    }

    fn check_known_bad(&self, dep: &Dependency) -> Option<RiskFlag> {
        for entry in &self.known_bad {
            let name_match = entry.org == dep.org
                && (entry.name == dep.name || dep.name.starts_with(&entry.name));

            if name_match {
                let dep_ver = parse_version_loose(&dep.version);
                let threshold = parse_version_loose(&entry.risky_below);
                let is_dynamic = dep.version.contains('+') || dep.version == "latest.release";

                if let (Some(dv), Some(tv)) = (dep_ver, threshold) {
                    if dv < tv {
                        let reason = if is_dynamic {
                            format!(
                                "{} (declared as '{}', resolved minimum: {})",
                                entry.reason, dep.version, dv
                            )
                        } else {
                            entry.reason.clone()
                        };
                        return Some(RiskFlag {
                            dependency: dep.clone(),
                            severity: Severity::from_str(&entry.severity),
                            reason,
                            cve_ids: entry.cve_ids.clone(),
                            risk_type: RiskType::KnownVulnerable,
                            fix_suggestion: Some(format!("Upgrade to >= {}", entry.risky_below)),
                        });
                    }
                } else {
                    // Can't parse version — flag as info
                    return Some(RiskFlag {
                        dependency: dep.clone(),
                        severity: Severity::Info,
                        reason: format!(
                            "Could not parse version '{}'; known risky below {}",
                            dep.version, entry.risky_below
                        ),
                        cve_ids: entry.cve_ids.clone(),
                        risk_type: RiskType::KnownVulnerable,
                        fix_suggestion: Some(format!("Verify version >= {}", entry.risky_below)),
                    });
                }
            }
        }
        None
    }

    fn check_staleness(&self, dep: &Dependency) -> Option<RiskFlag> {
        // Heuristics for obviously old versions:
        // - Major version 0 or 1 on things that have been around forever
        // - Versions with dates like 20150101
        let ver = dep.version.trim();

        // Version starts with 0.x
        if ver.starts_with("0.") {
            return Some(RiskFlag {
                dependency: dep.clone(),
                severity: Severity::Low,
                reason: "Pre-release (0.x) version in production dependency".to_string(),
                cve_ids: vec![],
                risk_type: RiskType::Outdated,
                fix_suggestion: Some("Evaluate if a stable release is available".to_string()),
            });
        }

        // Very old date-based version (< 2018)
        if let Some(year) = extract_year_from_version(ver) {
            if year < 2018 {
                return Some(RiskFlag {
                    dependency: dep.clone(),
                    severity: Severity::Medium,
                    reason: format!(
                        "Dependency version appears to be from {} (>5 years old)",
                        year
                    ),
                    cve_ids: vec![],
                    risk_type: RiskType::Outdated,
                    fix_suggestion: Some("Check for newer releases".to_string()),
                });
            }
        }

        // Check for known deprecated artifact IDs
        let deprecated_patterns = [
            ("log4j", "log4j", "Migrate to logback or log4j2"),
            (
                "javax.servlet",
                "servlet-api",
                "Use jakarta.servlet:jakarta.servlet-api",
            ),
            ("commons-lang", "commons-lang", "Use commons-lang3"),
            (
                "org.codehaus.jackson",
                "jackson-core-asl",
                "Migrate to com.fasterxml.jackson",
            ),
        ];

        for (dorg, dname, fix) in &deprecated_patterns {
            if dep.org.contains(dorg) && dep.name.contains(dname) {
                return Some(RiskFlag {
                    dependency: dep.clone(),
                    severity: Severity::Medium,
                    reason: format!("Deprecated artifact: {}:{}", dep.org, dep.name),
                    cve_ids: vec![],
                    risk_type: RiskType::Outdated,
                    fix_suggestion: Some(fix.to_string()),
                });
            }
        }

        None
    }

    fn check_osv(&self, dep: &Dependency) -> Result<Vec<RiskFlag>> {
        let cache_key = format!("{}:{}:{}", dep.org, dep.name, dep.version);

        // Try cache first (unless --no-cache)
        if !self.no_cache {
            if let Some(cached_body) = read_osv_cache(&cache_key) {
                return Self::parse_osv_response(dep, &cached_body);
            }
        }

        let payload = serde_json::json!({
            "version": dep.version,
            "package": {
                "name": format!("{}:{}", dep.org, dep.name),
                "ecosystem": "Maven"
            }
        });
        let payload_str = serde_json::to_string(&payload)?;

        // Use ureq HTTP client instead of curl subprocess
        let response = ureq::post("https://api.osv.dev/v1/query")
            .set("Content-Type", "application/json")
            .timeout(std::time::Duration::from_secs(5))
            .send_string(&payload_str);

        match response {
            Ok(resp) => {
                let body = resp.into_string().unwrap_or_default();

                // Cache the response
                write_osv_cache(&cache_key, &body);

                Self::parse_osv_response(dep, &body)
            }
            Err(_) => Ok(vec![]),
        }
    }

    fn parse_osv_response(dep: &Dependency, body: &str) -> Result<Vec<RiskFlag>> {
        let osv: OsvResponse = serde_json::from_str(body).unwrap_or(OsvResponse { vulns: None });
        let mut flags = Vec::new();

        if let Some(vulns) = osv.vulns {
            for vuln in vulns {
                let severity = infer_severity_from_osv(&vuln);
                flags.push(RiskFlag {
                    dependency: dep.clone(),
                    severity,
                    reason: vuln.summary.unwrap_or_else(|| vuln.id.clone()),
                    cve_ids: vec![vuln.id],
                    risk_type: RiskType::OsvAdvisory,
                    fix_suggestion: None,
                });
            }
        }
        Ok(flags)
    }
}

/// Get the OSV cache directory path
fn osv_cache_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home)
        .join(".cache")
        .join("scala-dep-scan")
        .join("osv")
}

/// Read a cached OSV response if it exists and is within TTL
fn read_osv_cache(cache_key: &str) -> Option<String> {
    let cache_file = osv_cache_dir().join(sanitize_cache_key(cache_key));
    if !cache_file.exists() {
        return None;
    }

    // Check TTL
    if let Ok(metadata) = fs::metadata(&cache_file) {
        if let Ok(modified) = metadata.modified() {
            if let Ok(elapsed) = modified.elapsed() {
                if elapsed.as_secs() > CACHE_TTL_SECS {
                    // Expired
                    let _ = fs::remove_file(&cache_file);
                    return None;
                }
            }
        }
    }

    fs::read_to_string(&cache_file).ok()
}

/// Write an OSV response to the cache
fn write_osv_cache(cache_key: &str, body: &str) {
    let cache_dir = osv_cache_dir();
    let _ = fs::create_dir_all(&cache_dir);
    let cache_file = cache_dir.join(sanitize_cache_key(cache_key));
    let _ = fs::write(&cache_file, body);
}

/// Sanitize a cache key to be filesystem-safe
fn sanitize_cache_key(key: &str) -> String {
    key.replace(':', "_").replace('/', "_") + ".json"
}

fn parse_version_loose(v: &str) -> Option<Version> {
    let trimmed = v.trim();
    // Handle SBT dynamic versions early, before any splitting
    if trimmed == "latest.release" || trimmed == "latest.integration" {
        return None;
    }
    // "2.3.+" -> "2.3", "1.+" -> "1" — treat as minimum version in range
    let trimmed = if trimmed.ends_with(".+") {
        &trimmed[..trimmed.len() - 2]
    } else {
        trimmed
    };
    let cleaned = trimmed.split('+').next().unwrap_or(trimmed).trim();
    // Try direct parse
    if let Ok(sv) = Version::parse(cleaned) {
        return Some(sv);
    }
    // Try padding: "2.8" -> "2.8.0"
    let parts: Vec<&str> = cleaned.split('.').collect();
    match parts.len() {
        1 => Version::parse(&format!("{}.0.0", parts[0])).ok(),
        2 => Version::parse(&format!("{}.{}.0", parts[0], parts[1])).ok(),
        _ => {
            // Strip non-numeric suffix: "2.13.1-SNAPSHOT" -> "2.13.1"
            let base = cleaned.splitn(4, '.').take(3).collect::<Vec<_>>().join(".");
            let base = base.split('-').next().unwrap_or(&base).to_string();
            Version::parse(&base).ok()
        }
    }
}

fn extract_year_from_version(v: &str) -> Option<u32> {
    let re = regex::Regex::new(r"(20\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])").ok()?;
    if let Some(cap) = re.captures(v) {
        return cap[1].parse().ok();
    }
    // Also catch "20XX" year-only prefixes
    let re2 = regex::Regex::new(r"^(19|20)(\d{2})").ok()?;
    if let Some(cap) = re2.captures(v) {
        let full: u32 = format!("{}{}", &cap[1], &cap[2]).parse().ok()?;
        return Some(full);
    }
    None
}

fn infer_severity_from_osv(vuln: &crate::types::OsvVuln) -> Severity {
    if let Some(severities) = &vuln.severity {
        for s in severities {
            if s.sev_type == "CVSS_V3" {
                // Parse CVSS base score from vector string or numeric
                if let Ok(score) = s.score.parse::<f32>() {
                    return cvss_to_severity(score);
                }
                // CVSS vector like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                // rough estimate: if C:H I:H A:H -> critical
                if s.score.contains("C:H") && s.score.contains("I:H") {
                    return Severity::Critical;
                } else if s.score.contains("C:H") || s.score.contains("I:H") {
                    return Severity::High;
                }
            }
        }
    }
    Severity::Medium
}

fn cvss_to_severity(score: f32) -> Severity {
    match score as u8 {
        0 => Severity::Info,
        1..=3 => Severity::Low,
        4..=6 => Severity::Medium,
        7..=8 => Severity::High,
        _ => Severity::Critical,
    }
}
