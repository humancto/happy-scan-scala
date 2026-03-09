use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub org: String,
    pub name: String,
    pub version: String,
    pub scope: Option<String>,
    pub cross_compiled: bool,
    pub source_file: String,
    pub is_transitive: bool,
}

impl Dependency {
    pub fn coord(&self) -> String {
        format!("{}:{}", self.org, self.name)
    }

    pub fn full_coord(&self) -> String {
        format!("{}:{}:{}", self.org, self.name, self.version)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskyDepEntry {
    pub org: String,
    pub name: String,
    pub risky_below: String,
    pub reason: String,
    pub severity: String,
    pub cve_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFlag {
    pub dependency: Dependency,
    pub severity: Severity,
    pub reason: String,
    pub cve_ids: Vec<String>,
    pub risk_type: RiskType,
    pub fix_suggestion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(&self) -> &str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskType {
    KnownVulnerable,
    Outdated,
    OsvAdvisory,
}

impl RiskType {
    pub fn label(&self) -> &str {
        match self {
            RiskType::KnownVulnerable => "KNOWN-CVE",
            RiskType::Outdated => "OUTDATED",
            RiskType::OsvAdvisory => "OSV-ADVISORY",
        }
    }
}

#[derive(Debug)]
pub struct ParsedProject {
    pub root: PathBuf,
    pub build_files: Vec<PathBuf>,
    pub lock_files: Vec<PathBuf>,
    pub modules: Vec<SbtModule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbtModule {
    pub name: String,
    pub path: String,
    pub deps: Vec<Dependency>,
    pub depends_on: Vec<String>,
    pub aggregates: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CodeReference {
    pub dep_coord: String,
    pub file: String,
    pub line_number: usize,
    pub line_content: String,
    pub import_path: String,
}

/// Verdict for a single dependency's actual usage in code
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UsageVerdict {
    /// Imported AND symbols actively used in file bodies
    Active,
    /// Imported but the imported symbols never appear in file bodies
    DeadImport,
    /// No imports and no symbol usage found anywhere
    Unused,
    /// Likely runtime-injected (guice, play plugins, etc.) — not a real unused dep
    RuntimeOnly,
}

impl UsageVerdict {
    pub fn label(&self) -> &str {
        match self {
            UsageVerdict::Active => "ACTIVE",
            UsageVerdict::DeadImport => "DEAD IMPORT",
            UsageVerdict::Unused => "UNUSED",
            UsageVerdict::RuntimeOnly => "RUNTIME",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepUsageReport {
    pub coord: String,
    pub version: String,
    pub is_direct: bool,
    pub verdict: UsageVerdict,
    /// Files that import this dep
    pub import_files: Vec<String>,
    /// Files where symbols from this dep are actually used in code body
    pub usage_files: Vec<String>,
    /// Distinct symbol names found in code body (e.g. "AmazonS3", "ObjectMapper")
    pub symbols_found: Vec<String>,
    /// Total body-level references count
    pub usage_count: usize,
    /// Source file where this dep is declared (build.sbt, lock.sbt, etc.)
    pub source_file: String,
}

/// Classification for transitive (lock.sbt) dependencies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransitiveClassification {
    /// Linked to an active direct dependency (org match, version cluster, or known chain)
    LinkedTo {
        parent_coord: String,
        reason: String,
    },
    /// No code references and no link to any active direct dep — likely orphaned
    LikelyOrphaned,
    /// Has direct code references (imports or symbol usage)
    CodeReferenced,
    /// Identified as a runtime-only dependency
    RuntimeTransitive,
}

impl TransitiveClassification {
    pub fn label(&self) -> &str {
        match self {
            TransitiveClassification::LinkedTo { .. } => "LINKED",
            TransitiveClassification::LikelyOrphaned => "LIKELY-ORPHANED",
            TransitiveClassification::CodeReferenced => "CODE-REFERENCED",
            TransitiveClassification::RuntimeTransitive => "RUNTIME",
        }
    }

    pub fn is_orphaned(&self) -> bool {
        matches!(self, TransitiveClassification::LikelyOrphaned)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OsvResponse {
    pub vulns: Option<Vec<OsvVuln>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OsvVuln {
    pub id: String,
    pub summary: Option<String>,
    pub database_specific: Option<serde_json::Value>,
    pub severity: Option<Vec<OsvSeverity>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OsvSeverity {
    #[serde(rename = "type")]
    pub sev_type: String,
    pub score: String,
}
