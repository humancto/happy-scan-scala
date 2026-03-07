// License compliance module
// Queries Maven Central for license info and enforces policy.
// Self-contained — uses curl subprocess (same pattern as risk.rs OSV code).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// License classification categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LicenseClassification {
    Permissive,
    WeakCopyleft,
    StrongCopyleft,
    Unknown,
}

impl LicenseClassification {
    pub fn label(&self) -> &str {
        match self {
            LicenseClassification::Permissive => "PERMISSIVE",
            LicenseClassification::WeakCopyleft => "WEAK-COPYLEFT",
            LicenseClassification::StrongCopyleft => "STRONG-COPYLEFT",
            LicenseClassification::Unknown => "UNKNOWN",
        }
    }
}

/// License information for a single dependency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseInfo {
    pub coord: String,
    pub version: String,
    pub license_name: String,
    pub license_url: String,
    pub classification: LicenseClassification,
}

/// Policy violation found during license check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseViolation {
    pub coord: String,
    pub version: String,
    pub license_name: String,
    pub classification: LicenseClassification,
    pub reason: String,
}

/// License policy configuration
#[derive(Debug, Clone)]
pub struct LicensePolicy {
    pub allow_list: Vec<String>, // Allowed SPDX IDs
    pub deny_list: Vec<String>,  // Denied SPDX IDs
}

impl LicensePolicy {
    pub fn new() -> Self {
        Self {
            allow_list: Vec::new(),
            deny_list: Vec::new(),
        }
    }

    /// Parse policy from CLI string: "allow:MIT,Apache-2.0 deny:GPL-3.0"
    pub fn from_str(s: &str) -> Self {
        let mut policy = Self::new();
        for part in s.split_whitespace() {
            if let Some(ids) = part.strip_prefix("allow:") {
                policy
                    .allow_list
                    .extend(ids.split(',').map(|s| s.trim().to_string()));
            } else if let Some(ids) = part.strip_prefix("deny:") {
                policy
                    .deny_list
                    .extend(ids.split(',').map(|s| s.trim().to_string()));
            }
        }
        policy
    }

    /// Check whether a license violates policy
    pub fn check(&self, info: &LicenseInfo) -> Option<LicenseViolation> {
        let normalized = normalize_spdx(&info.license_name);

        // Check deny list first
        for denied in &self.deny_list {
            if normalized.eq_ignore_ascii_case(denied) {
                return Some(LicenseViolation {
                    coord: info.coord.clone(),
                    version: info.version.clone(),
                    license_name: info.license_name.clone(),
                    classification: info.classification.clone(),
                    reason: format!("License '{}' is on the deny list", info.license_name),
                });
            }
        }

        // If allow list is non-empty, only those licenses are permitted
        if !self.allow_list.is_empty() {
            let is_allowed = self
                .allow_list
                .iter()
                .any(|a| normalized.eq_ignore_ascii_case(a));
            if !is_allowed && normalized != "unknown" {
                return Some(LicenseViolation {
                    coord: info.coord.clone(),
                    version: info.version.clone(),
                    license_name: info.license_name.clone(),
                    classification: info.classification.clone(),
                    reason: format!("License '{}' is not on the allow list", info.license_name),
                });
            }
        }

        None
    }
}

/// Minimal dependency info for license scanning
#[derive(Debug, Clone)]
pub struct LicenseDep {
    pub org: String,
    pub name: String,
    pub version: String,
}

impl LicenseDep {
    pub fn coord(&self) -> String {
        format!("{}:{}", self.org, self.name)
    }
}

/// Cache for license lookups — maps coord to LicenseInfo
pub struct LicenseCache {
    entries: HashMap<String, LicenseInfo>,
    cache_dir: Option<String>,
}

impl LicenseCache {
    pub fn new(cache_dir: Option<String>) -> Self {
        let mut cache = Self {
            entries: HashMap::new(),
            cache_dir: cache_dir.clone(),
        };

        // Load from disk cache if available
        if let Some(dir) = &cache_dir {
            let path = format!("{}/license_cache.json", dir);
            if let Ok(data) = std::fs::read_to_string(&path) {
                if let Ok(entries) = serde_json::from_str::<HashMap<String, LicenseInfo>>(&data) {
                    cache.entries = entries;
                }
            }
        }

        cache
    }

    pub fn get(&self, coord: &str) -> Option<&LicenseInfo> {
        self.entries.get(coord)
    }

    pub fn insert(&mut self, coord: String, info: LicenseInfo) {
        self.entries.insert(coord, info);
    }

    pub fn save(&self) {
        if let Some(dir) = &self.cache_dir {
            let _ = std::fs::create_dir_all(dir);
            let path = format!("{}/license_cache.json", dir);
            if let Ok(json) = serde_json::to_string_pretty(&self.entries) {
                let _ = std::fs::write(&path, json);
            }
        }
    }
}

/// Scan licenses for a list of dependencies
pub fn scan_licenses(deps: &[LicenseDep], cache: &mut LicenseCache) -> Vec<LicenseInfo> {
    let mut results: Vec<LicenseInfo> = Vec::new();

    for dep in deps {
        let coord = dep.coord();

        // Check cache first
        if let Some(cached) = cache.get(&coord) {
            results.push(cached.clone());
            continue;
        }

        // Query Maven Central
        let info = query_maven_license(dep);
        cache.insert(coord, info.clone());
        results.push(info);
    }

    cache.save();
    results
}

/// Query Maven Central Solr API for license information
fn query_maven_license(dep: &LicenseDep) -> LicenseInfo {
    let url = format!(
        "https://search.maven.org/solrsearch/select?q=g:\"{}\"%%20AND%%20a:\"{}\"&rows=1&wt=json",
        dep.org, dep.name
    );

    let output = std::process::Command::new("curl")
        .args(["-s", "--max-time", "5", &url])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let body = String::from_utf8_lossy(&out.stdout);
            parse_maven_license_response(&body, dep)
        }
        _ => LicenseInfo {
            coord: dep.coord(),
            version: dep.version.clone(),
            license_name: "Unknown".to_string(),
            license_url: String::new(),
            classification: LicenseClassification::Unknown,
        },
    }
}

/// Parse Maven Central JSON response for license info
fn parse_maven_license_response(body: &str, dep: &LicenseDep) -> LicenseInfo {
    let default = LicenseInfo {
        coord: dep.coord(),
        version: dep.version.clone(),
        license_name: "Unknown".to_string(),
        license_url: String::new(),
        classification: LicenseClassification::Unknown,
    };

    let parsed: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return default,
    };

    // Maven Central Solr response: response.docs[0]
    let docs = match parsed["response"]["docs"].as_array() {
        Some(d) if !d.is_empty() => d,
        _ => return default,
    };

    let doc = &docs[0];

    // The Solr API doesn't directly return license info in search results.
    // We'll try the POM metadata approach via a second curl if needed.
    // For now, attempt to get from the search result if available.
    // Maven Central sometimes includes 'p' (packaging) but not license directly.
    // We'll do a POM fetch for license info.

    let pom_url = format!(
        "https://repo1.maven.org/maven2/{}/{}/{}/{}-{}.pom",
        dep.org.replace('.', "/"),
        dep.name,
        dep.version,
        dep.name,
        dep.version
    );

    let pom_output = std::process::Command::new("curl")
        .args(["-s", "--max-time", "5", &pom_url])
        .output();

    match pom_output {
        Ok(out) if out.status.success() => {
            let pom = String::from_utf8_lossy(&out.stdout);
            parse_license_from_pom(&pom, dep)
        }
        _ => {
            // Fallback: try known coordinates
            let guessed = guess_license_from_coord(dep);
            if guessed.license_name != "Unknown" {
                guessed
            } else {
                default
            }
        }
    }
}

/// Extract license from POM XML (simple regex-based, no XML parser dep)
fn parse_license_from_pom(pom: &str, dep: &LicenseDep) -> LicenseInfo {
    // Look for <licenses><license><name>...</name><url>...</url></license></licenses>
    let name_re = regex::Regex::new(r"<license>\s*<name>([^<]+)</name>").ok();
    let url_re =
        regex::Regex::new(r"<license>[^<]*(?:<name>[^<]*</name>)?\s*<url>([^<]+)</url>").ok();

    let license_name = name_re
        .and_then(|re| re.captures(pom))
        .map(|c| c[1].trim().to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    let license_url = url_re
        .and_then(|re| re.captures(pom))
        .map(|c| c[1].trim().to_string())
        .unwrap_or_default();

    let classification = classify_license(&license_name);

    LicenseInfo {
        coord: dep.coord(),
        version: dep.version.clone(),
        license_name,
        license_url,
        classification,
    }
}

/// Guess license from well-known coordinates (fallback when API is unavailable)
fn guess_license_from_coord(dep: &LicenseDep) -> LicenseInfo {
    let known: &[(&str, &str, &str)] = &[
        (
            "com.typesafe.play",
            "Apache-2.0",
            "https://www.apache.org/licenses/LICENSE-2.0",
        ),
        (
            "com.typesafe.akka",
            "Apache-2.0",
            "https://www.apache.org/licenses/LICENSE-2.0",
        ),
        (
            "com.typesafe",
            "Apache-2.0",
            "https://www.apache.org/licenses/LICENSE-2.0",
        ),
        (
            "org.scala-lang",
            "Apache-2.0",
            "https://www.apache.org/licenses/LICENSE-2.0",
        ),
        (
            "org.apache.",
            "Apache-2.0",
            "https://www.apache.org/licenses/LICENSE-2.0",
        ),
        (
            "com.google.guava",
            "Apache-2.0",
            "https://www.apache.org/licenses/LICENSE-2.0",
        ),
        (
            "com.fasterxml.jackson",
            "Apache-2.0",
            "https://www.apache.org/licenses/LICENSE-2.0",
        ),
        (
            "io.netty",
            "Apache-2.0",
            "https://www.apache.org/licenses/LICENSE-2.0",
        ),
        (
            "com.amazonaws",
            "Apache-2.0",
            "https://www.apache.org/licenses/LICENSE-2.0",
        ),
        (
            "software.amazon.awssdk",
            "Apache-2.0",
            "https://www.apache.org/licenses/LICENSE-2.0",
        ),
        ("org.slf4j", "MIT", "https://opensource.org/licenses/MIT"),
        (
            "ch.qos.logback",
            "LGPL-2.1",
            "https://www.gnu.org/licenses/lgpl-2.1.html",
        ),
        (
            "org.postgresql",
            "BSD-2-Clause",
            "https://opensource.org/licenses/BSD-2-Clause",
        ),
        (
            "io.circe",
            "Apache-2.0",
            "https://www.apache.org/licenses/LICENSE-2.0",
        ),
        (
            "org.http4s",
            "Apache-2.0",
            "https://www.apache.org/licenses/LICENSE-2.0",
        ),
    ];

    for (org_prefix, license, url) in known {
        if dep.org.starts_with(org_prefix) {
            let classification = classify_license(license);
            return LicenseInfo {
                coord: dep.coord(),
                version: dep.version.clone(),
                license_name: license.to_string(),
                license_url: url.to_string(),
                classification,
            };
        }
    }

    LicenseInfo {
        coord: dep.coord(),
        version: dep.version.clone(),
        license_name: "Unknown".to_string(),
        license_url: String::new(),
        classification: LicenseClassification::Unknown,
    }
}

/// Classify a license name into categories
pub fn classify_license(name: &str) -> LicenseClassification {
    let lower = name.to_lowercase();

    // Permissive licenses
    let permissive_patterns = [
        "mit",
        "apache",
        "bsd",
        "isc",
        "unlicense",
        "wtfpl",
        "cc0",
        "public domain",
        "0bsd",
        "zlib",
        "boost",
        "unicode",
        "artistic",
    ];
    for p in &permissive_patterns {
        if lower.contains(p) {
            return LicenseClassification::Permissive;
        }
    }

    // Strong copyleft
    let strong_copyleft = [
        "agpl",
        "gpl-3",
        "gpl-2",
        "gplv3",
        "gplv2",
        "gnu general public",
    ];
    for p in &strong_copyleft {
        if lower.contains(p) {
            // But check if it's actually LGPL (weak copyleft)
            if lower.contains("lgpl") || lower.contains("lesser") {
                return LicenseClassification::WeakCopyleft;
            }
            return LicenseClassification::StrongCopyleft;
        }
    }

    // Weak copyleft
    let weak_copyleft = [
        "lgpl",
        "lesser",
        "mpl",
        "mozilla",
        "cpl",
        "common public",
        "epl",
        "eclipse",
        "cecill",
    ];
    for p in &weak_copyleft {
        if lower.contains(p) {
            return LicenseClassification::WeakCopyleft;
        }
    }

    LicenseClassification::Unknown
}

/// Normalize license name to approximate SPDX ID
fn normalize_spdx(name: &str) -> String {
    let lower = name.to_lowercase();
    if lower.contains("apache") && lower.contains("2") {
        return "Apache-2.0".to_string();
    }
    if lower == "mit" || lower.contains("mit license") {
        return "MIT".to_string();
    }
    if lower.contains("bsd") && lower.contains("3") {
        return "BSD-3-Clause".to_string();
    }
    if lower.contains("bsd") && lower.contains("2") {
        return "BSD-2-Clause".to_string();
    }
    if (lower.contains("lgpl") || lower.contains("lesser")) && lower.contains("2.1") {
        return "LGPL-2.1".to_string();
    }
    if (lower.contains("lgpl") || lower.contains("lesser")) && lower.contains("3") {
        return "LGPL-3.0".to_string();
    }
    if lower.contains("agpl") {
        return "AGPL-3.0".to_string();
    }
    if lower.contains("gpl") && lower.contains("3") {
        return "GPL-3.0".to_string();
    }
    if lower.contains("gpl") && lower.contains("2") {
        return "GPL-2.0".to_string();
    }
    if lower.contains("mpl") && lower.contains("2") {
        return "MPL-2.0".to_string();
    }
    if lower.contains("eclipse") || lower.contains("epl") {
        return "EPL-2.0".to_string();
    }
    if lower.contains("isc") {
        return "ISC".to_string();
    }
    if lower.contains("unlicense") {
        return "Unlicense".to_string();
    }
    // Return as-is if no match
    name.to_string()
}

/// Format license report for terminal output (standalone, no crate::report dependency)
pub fn format_license_report(licenses: &[LicenseInfo], violations: &[LicenseViolation]) -> String {
    let mut out = String::new();

    out.push_str(
        "== License Compliance Report ================================================\n\n",
    );

    // Summary counts
    let permissive = licenses
        .iter()
        .filter(|l| l.classification == LicenseClassification::Permissive)
        .count();
    let weak = licenses
        .iter()
        .filter(|l| l.classification == LicenseClassification::WeakCopyleft)
        .count();
    let strong = licenses
        .iter()
        .filter(|l| l.classification == LicenseClassification::StrongCopyleft)
        .count();
    let unknown = licenses
        .iter()
        .filter(|l| l.classification == LicenseClassification::Unknown)
        .count();

    out.push_str(&format!(
        "  {} Permissive  |  {} Weak Copyleft  |  {} Strong Copyleft  |  {} Unknown\n\n",
        permissive, weak, strong, unknown
    ));

    // List each dep
    for info in licenses {
        let marker = match info.classification {
            LicenseClassification::Permissive => "[OK]",
            LicenseClassification::WeakCopyleft => "[!!]",
            LicenseClassification::StrongCopyleft => "[XX]",
            LicenseClassification::Unknown => "[??]",
        };
        out.push_str(&format!(
            "  {} {} : {} ({})\n",
            marker,
            info.coord,
            info.license_name,
            info.classification.label()
        ));
    }
    out.push('\n');

    // Violations
    if !violations.is_empty() {
        out.push_str("  POLICY VIOLATIONS:\n");
        out.push_str("  ─────────────────\n");
        for v in violations {
            out.push_str(&format!(
                "  [VIOLATION] {} - {} : {}\n",
                v.coord, v.license_name, v.reason
            ));
        }
        out.push('\n');
    }

    out
}

/// Format license report as JSON
pub fn format_license_json(licenses: &[LicenseInfo], violations: &[LicenseViolation]) -> String {
    let report = serde_json::json!({
        "licenses": licenses,
        "violations": violations,
        "summary": {
            "total": licenses.len(),
            "permissive": licenses.iter().filter(|l| l.classification == LicenseClassification::Permissive).count(),
            "weak_copyleft": licenses.iter().filter(|l| l.classification == LicenseClassification::WeakCopyleft).count(),
            "strong_copyleft": licenses.iter().filter(|l| l.classification == LicenseClassification::StrongCopyleft).count(),
            "unknown": licenses.iter().filter(|l| l.classification == LicenseClassification::Unknown).count(),
            "violations": violations.len(),
        }
    });
    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_permissive() {
        assert_eq!(classify_license("MIT"), LicenseClassification::Permissive);
        assert_eq!(
            classify_license("Apache License 2.0"),
            LicenseClassification::Permissive
        );
        assert_eq!(
            classify_license("BSD-3-Clause"),
            LicenseClassification::Permissive
        );
    }

    #[test]
    fn test_classify_copyleft() {
        assert_eq!(
            classify_license("GPL-3.0"),
            LicenseClassification::StrongCopyleft
        );
        assert_eq!(
            classify_license("LGPL-2.1"),
            LicenseClassification::WeakCopyleft
        );
        assert_eq!(
            classify_license("Mozilla Public License 2.0"),
            LicenseClassification::WeakCopyleft
        );
    }

    #[test]
    fn test_policy_deny() {
        let policy = LicensePolicy::from_str("deny:GPL-3.0,AGPL-3.0");
        let info = LicenseInfo {
            coord: "org:lib".to_string(),
            version: "1.0".to_string(),
            license_name: "GPL-3.0".to_string(),
            license_url: String::new(),
            classification: LicenseClassification::StrongCopyleft,
        };
        assert!(policy.check(&info).is_some());
    }

    #[test]
    fn test_policy_allow() {
        let policy = LicensePolicy::from_str("allow:MIT,Apache-2.0");
        let info = LicenseInfo {
            coord: "org:lib".to_string(),
            version: "1.0".to_string(),
            license_name: "GPL-3.0".to_string(),
            license_url: String::new(),
            classification: LicenseClassification::StrongCopyleft,
        };
        assert!(policy.check(&info).is_some());
    }

    #[test]
    fn test_normalize_spdx() {
        assert_eq!(
            normalize_spdx("The Apache Software License, Version 2.0"),
            "Apache-2.0"
        );
        assert_eq!(normalize_spdx("MIT"), "MIT");
        assert_eq!(
            normalize_spdx("GNU Lesser General Public License v2.1"),
            "LGPL-2.1"
        );
    }
}
