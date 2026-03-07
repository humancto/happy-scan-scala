use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::types::{RiskFlag, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub version: u32,
    #[serde(default = "default_severity")]
    pub severity_threshold: String,
    #[serde(default)]
    pub ignore: Vec<IgnoreEntry>,
}

fn default_severity() -> String {
    "low".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IgnoreEntry {
    /// Dependency coordinate to ignore (e.g. "com.typesafe.play:play")
    #[serde(default)]
    pub coord: Option<String>,
    /// CVE id to ignore (e.g. "CVE-2015-6420")
    #[serde(default)]
    pub cve: Option<String>,
    /// Human-readable reason for ignoring
    #[serde(default)]
    pub reason: Option<String>,
    /// Expiry date in YYYY-MM-DD format; after this date the ignore is no longer applied
    #[serde(default)]
    pub expires: Option<String>,
}

impl Config {
    /// Load config from `.scala-dep-scan.yaml` in the given project root.
    /// Returns a default (empty) config if the file does not exist.
    pub fn load(project_root: &Path) -> Result<Self> {
        let config_path = project_root.join(".scala-dep-scan.yaml");
        if !config_path.exists() {
            return Ok(Self {
                version: 1,
                severity_threshold: default_severity(),
                ignore: vec![],
            });
        }
        let content = fs::read_to_string(&config_path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    /// Generate a config file with all current findings pre-populated as ignored.
    pub fn generate_init(project_root: &Path, flags: &[RiskFlag]) -> Result<()> {
        let today = chrono_today_plus_months(6);
        let mut entries: Vec<IgnoreEntry> = Vec::new();

        // Collect unique coords
        let mut seen_coords = std::collections::HashSet::new();
        for flag in flags {
            let coord = flag.dependency.coord();
            if seen_coords.insert(coord.clone()) {
                entries.push(IgnoreEntry {
                    coord: Some(coord),
                    cve: None,
                    reason: Some(format!("TODO: {}", flag.reason)),
                    expires: Some(today.clone()),
                });
            }
            // Also add individual CVEs
            for cve in &flag.cve_ids {
                entries.push(IgnoreEntry {
                    coord: None,
                    cve: Some(cve.clone()),
                    reason: Some(format!("TODO: review {}", cve)),
                    expires: Some(today.clone()),
                });
            }
        }

        // Dedup CVE entries
        let mut seen_cves = std::collections::HashSet::new();
        entries.retain(|e| {
            if let Some(cve) = &e.cve {
                seen_cves.insert(cve.clone())
            } else {
                true
            }
        });

        let config = Config {
            version: 1,
            severity_threshold: "low".to_string(),
            ignore: entries,
        };

        let yaml = serde_yaml::to_string(&config)?;
        let config_path = project_root.join(".scala-dep-scan.yaml");
        fs::write(&config_path, &yaml)?;
        Ok(())
    }

    /// Filter out risk flags that match ignore rules. Returns (kept_flags, ignored_count).
    pub fn filter_flags(&self, flags: Vec<RiskFlag>) -> (Vec<RiskFlag>, usize) {
        let today = today_string();
        let mut ignored = 0usize;

        let kept: Vec<RiskFlag> = flags
            .into_iter()
            .filter(|flag| {
                for entry in &self.ignore {
                    // Check expiry
                    if let Some(expires) = &entry.expires {
                        if expires.as_str() < today.as_str() {
                            // Expired ignore rule — do not apply
                            continue;
                        }
                    }

                    // Match by coord
                    if let Some(coord) = &entry.coord {
                        if flag.dependency.coord() == *coord {
                            ignored += 1;
                            return false;
                        }
                    }

                    // Match by CVE
                    if let Some(cve) = &entry.cve {
                        if flag.cve_ids.contains(cve) {
                            ignored += 1;
                            return false;
                        }
                    }
                }
                true
            })
            .collect();

        (kept, ignored)
    }

    /// Get severity threshold from config
    pub fn severity_threshold(&self) -> Severity {
        Severity::from_str(&self.severity_threshold)
    }
}

/// Returns today's date as YYYY-MM-DD string
fn today_string() -> String {
    // Use a simple approach: read system time
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Convert epoch seconds to date (rough but functional)
    epoch_to_date_string(now)
}

/// Simple epoch to YYYY-MM-DD conversion
fn epoch_to_date_string(epoch_secs: u64) -> String {
    // Days since 1970-01-01
    let days = (epoch_secs / 86400) as i64;
    let (year, month, day) = days_to_ymd(days);
    format!("{:04}-{:02}-{:02}", year, month, day)
}

fn days_to_ymd(days_since_epoch: i64) -> (i64, i64, i64) {
    // Algorithm from Howard Hinnant's date library
    let z = days_since_epoch + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Returns a date string ~6 months from now
fn chrono_today_plus_months(months: u32) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Add roughly 6 months worth of seconds
    let future = now + (months as u64) * 30 * 86400;
    epoch_to_date_string(future)
}
