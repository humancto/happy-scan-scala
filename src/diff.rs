//! Scan Diff / Comparison Mode
//!
//! Save scan results as a baseline and compare subsequent scans against it.
//! Self-contained — does not import from other project modules.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

// ── Baseline types ──────────────────────────────────────────────────────────

/// A serializable snapshot of a single risk flag.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct BaselineFlag {
    /// e.g. "com.typesafe.play:play-json"
    pub coord: String,
    /// Version when the baseline was captured
    pub version: String,
    /// Severity label: "Critical", "High", "Medium", "Low", "Info"
    pub severity: String,
    /// Risk type label: "KNOWN-CVE", "OUTDATED", "OSV-ADVISORY", "POLICY"
    pub risk_type: String,
    /// Human-readable reason
    pub reason: String,
    /// Associated CVE identifiers
    pub cve_ids: Vec<String>,
}

impl BaselineFlag {
    /// A stable identity key for deduplication / diffing.
    /// We consider a flag "the same" if coord + risk_type + reason match.
    pub fn identity_key(&self) -> String {
        format!("{}::{}::{}", self.coord, self.risk_type, self.reason)
    }
}

/// The full baseline file format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanBaseline {
    /// ISO-8601 timestamp when baseline was saved
    pub timestamp: String,
    /// Tool version
    pub tool_version: String,
    /// All risk flags at time of baseline
    pub flags: Vec<BaselineFlag>,
    /// Total direct dependency count
    pub direct_dep_count: usize,
    /// Total transitive dependency count
    pub transitive_dep_count: usize,
}

/// The result of comparing a current scan against a baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResult {
    pub new_flags: Vec<BaselineFlag>,
    pub resolved_flags: Vec<BaselineFlag>,
    pub unchanged_flags: Vec<BaselineFlag>,
    pub baseline_timestamp: String,
    pub baseline_direct_count: usize,
    pub baseline_transitive_count: usize,
    pub current_direct_count: usize,
    pub current_transitive_count: usize,
}

impl DiffResult {
    /// Returns true if there are new critical or high findings.
    pub fn has_new_critical_or_high(&self) -> bool {
        self.new_flags.iter().any(|f| {
            let s = f.severity.to_lowercase();
            s == "critical" || s == "high"
        })
    }

    /// Suggested exit code: 0 if no new critical/high, 1 if new high, 2 if new critical.
    pub fn exit_code(&self) -> i32 {
        let has_critical = self
            .new_flags
            .iter()
            .any(|f| f.severity.to_lowercase() == "critical");
        let has_high = self
            .new_flags
            .iter()
            .any(|f| f.severity.to_lowercase() == "high");
        if has_critical {
            2
        } else if has_high {
            1
        } else {
            0
        }
    }

    /// Produce a human-readable summary.
    pub fn summary(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "Baseline: {} ({} direct, {} transitive)\n",
            self.baseline_timestamp, self.baseline_direct_count, self.baseline_transitive_count
        ));
        out.push_str(&format!(
            "Current:  {} direct, {} transitive\n\n",
            self.current_direct_count, self.current_transitive_count
        ));
        out.push_str(&format!("NEW findings:       {}\n", self.new_flags.len()));
        out.push_str(&format!(
            "RESOLVED findings:  {}\n",
            self.resolved_flags.len()
        ));
        out.push_str(&format!(
            "UNCHANGED findings: {}\n",
            self.unchanged_flags.len()
        ));

        if !self.new_flags.is_empty() {
            out.push_str("\n--- NEW ---\n");
            for f in &self.new_flags {
                out.push_str(&format!(
                    "  [{:>8}] {} {} - {}\n",
                    f.severity, f.coord, f.risk_type, f.reason
                ));
            }
        }

        if !self.resolved_flags.is_empty() {
            out.push_str("\n--- RESOLVED ---\n");
            for f in &self.resolved_flags {
                out.push_str(&format!(
                    "  [{:>8}] {} {} - {}\n",
                    f.severity, f.coord, f.risk_type, f.reason
                ));
            }
        }

        out
    }
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Save a baseline JSON file from the current scan's risk flags.
///
/// `flags_json` should be a JSON array of risk flag objects with the shape:
/// ```json
/// [{ "dependency": { "org": "...", "name": "...", "version": "..." },
///    "severity": "High", "reason": "...", "risk_type": "OUTDATED",
///    "cve_ids": [] }]
/// ```
pub fn save_baseline(
    path: &Path,
    flags_json: &serde_json::Value,
    direct_count: usize,
    transitive_count: usize,
) -> Result<(), String> {
    let flags = json_to_baseline_flags(flags_json);
    let baseline = ScanBaseline {
        timestamp: current_timestamp(),
        tool_version: "0.1.0".to_string(),
        flags,
        direct_dep_count: direct_count,
        transitive_dep_count: transitive_count,
    };
    let json = serde_json::to_string_pretty(&baseline)
        .map_err(|e| format!("Failed to serialize baseline: {}", e))?;
    fs::write(path, json)
        .map_err(|e| format!("Failed to write baseline to {}: {}", path.display(), e))?;
    Ok(())
}

/// Load a baseline from a JSON file.
pub fn load_baseline(path: &Path) -> Result<ScanBaseline, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read baseline {}: {}", path.display(), e))?;
    serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse baseline {}: {}", path.display(), e))
}

/// Compare current scan flags against a saved baseline.
pub fn compare(
    baseline: &ScanBaseline,
    current_flags_json: &serde_json::Value,
    current_direct_count: usize,
    current_transitive_count: usize,
) -> DiffResult {
    let current_flags = json_to_baseline_flags(current_flags_json);

    let baseline_keys: HashSet<String> = baseline.flags.iter().map(|f| f.identity_key()).collect();
    let current_keys: HashSet<String> = current_flags.iter().map(|f| f.identity_key()).collect();

    let new_flags: Vec<BaselineFlag> = current_flags
        .iter()
        .filter(|f| !baseline_keys.contains(&f.identity_key()))
        .cloned()
        .collect();

    let resolved_flags: Vec<BaselineFlag> = baseline
        .flags
        .iter()
        .filter(|f| !current_keys.contains(&f.identity_key()))
        .cloned()
        .collect();

    let unchanged_flags: Vec<BaselineFlag> = current_flags
        .iter()
        .filter(|f| baseline_keys.contains(&f.identity_key()))
        .cloned()
        .collect();

    DiffResult {
        new_flags,
        resolved_flags,
        unchanged_flags,
        baseline_timestamp: baseline.timestamp.clone(),
        baseline_direct_count: baseline.direct_dep_count,
        baseline_transitive_count: baseline.transitive_dep_count,
        current_direct_count,
        current_transitive_count,
    }
}

/// Produce a JSON report of the diff.
pub fn diff_to_json(diff: &DiffResult) -> String {
    serde_json::to_string_pretty(diff).unwrap_or_else(|_| "{}".to_string())
}

// ── Internal helpers ────────────────────────────────────────────────────────

fn json_to_baseline_flags(flags_json: &serde_json::Value) -> Vec<BaselineFlag> {
    let arr = match flags_json.as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };

    arr.iter()
        .filter_map(|v| {
            let dep = v.get("dependency").unwrap_or(v);
            let org = dep.get("org")?.as_str()?;
            let name = dep.get("name")?.as_str()?;
            let version = dep.get("version")?.as_str()?.to_string();
            let coord = format!("{}:{}", org, name);
            let severity = v.get("severity")?.as_str()?.to_string();
            let risk_type = v
                .get("risk_type")
                .and_then(|r| r.as_str())
                .unwrap_or("UNKNOWN")
                .to_string();
            let reason = v
                .get("reason")
                .and_then(|r| r.as_str())
                .unwrap_or("")
                .to_string();
            let cve_ids: Vec<String> = v
                .get("cve_ids")
                .and_then(|c| c.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|c| c.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            Some(BaselineFlag {
                coord,
                version,
                severity,
                risk_type,
                reason,
                cve_ids,
            })
        })
        .collect()
}

fn current_timestamp() -> String {
    // Simple UTC-ish timestamp without chrono dependency
    // We use a fallback approach
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    // Convert to rough ISO-8601
    let days = secs / 86400;
    let years = 1970 + days / 365;
    let remaining_days = days % 365;
    let months = remaining_days / 30 + 1;
    let day = remaining_days % 30 + 1;
    let hour = (secs % 86400) / 3600;
    let minute = (secs % 3600) / 60;
    let second = secs % 60;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        years, months, day, hour, minute, second
    )
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_flags_json() -> serde_json::Value {
        serde_json::json!([
            {
                "dependency": {"org": "com.typesafe.play", "name": "play-json", "version": "2.6.14"},
                "severity": "High",
                "reason": "Outdated dependency",
                "risk_type": "OUTDATED",
                "cve_ids": []
            },
            {
                "dependency": {"org": "com.fasterxml.jackson.core", "name": "jackson-databind", "version": "2.9.8"},
                "severity": "Critical",
                "reason": "Known CVE",
                "risk_type": "KNOWN-CVE",
                "cve_ids": ["CVE-2019-12345"]
            }
        ])
    }

    #[test]
    fn test_baseline_flags_roundtrip() {
        let flags = json_to_baseline_flags(&sample_flags_json());
        assert_eq!(flags.len(), 2);
        assert_eq!(flags[0].coord, "com.typesafe.play:play-json");
        assert_eq!(flags[1].severity, "Critical");
    }

    #[test]
    fn test_diff_new_finding() {
        let baseline_flags = serde_json::json!([
            {
                "dependency": {"org": "com.typesafe.play", "name": "play-json", "version": "2.6.14"},
                "severity": "High",
                "reason": "Outdated dependency",
                "risk_type": "OUTDATED",
                "cve_ids": []
            }
        ]);
        let baseline = ScanBaseline {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            tool_version: "0.1.0".to_string(),
            flags: json_to_baseline_flags(&baseline_flags),
            direct_dep_count: 10,
            transitive_dep_count: 50,
        };

        let current = sample_flags_json(); // has jackson-databind too
        let diff = compare(&baseline, &current, 11, 52);

        assert_eq!(diff.new_flags.len(), 1);
        assert_eq!(
            diff.new_flags[0].coord,
            "com.fasterxml.jackson.core:jackson-databind"
        );
        assert_eq!(diff.resolved_flags.len(), 0);
        assert_eq!(diff.unchanged_flags.len(), 1);
        assert!(diff.has_new_critical_or_high());
        assert_eq!(diff.exit_code(), 2); // new critical
    }

    #[test]
    fn test_diff_resolved_finding() {
        let baseline = ScanBaseline {
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            tool_version: "0.1.0".to_string(),
            flags: json_to_baseline_flags(&sample_flags_json()),
            direct_dep_count: 10,
            transitive_dep_count: 50,
        };

        // Current scan has only play-json, jackson was fixed
        let current = serde_json::json!([
            {
                "dependency": {"org": "com.typesafe.play", "name": "play-json", "version": "2.6.14"},
                "severity": "High",
                "reason": "Outdated dependency",
                "risk_type": "OUTDATED",
                "cve_ids": []
            }
        ]);
        let diff = compare(&baseline, &current, 10, 50);

        assert_eq!(diff.new_flags.len(), 0);
        assert_eq!(diff.resolved_flags.len(), 1);
        assert_eq!(
            diff.resolved_flags[0].coord,
            "com.fasterxml.jackson.core:jackson-databind"
        );
        assert!(!diff.has_new_critical_or_high());
        assert_eq!(diff.exit_code(), 0);
    }
}
