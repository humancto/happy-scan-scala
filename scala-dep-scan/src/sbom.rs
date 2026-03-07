// SBOM generation module: CycloneDX 1.5 and SPDX 2.3 JSON output
// Self-contained — does not import from crate types to avoid conflicts with other agents.

use serde::Serialize;
use std::collections::HashMap;

/// Minimal dependency info needed for SBOM generation
#[derive(Debug, Clone)]
pub struct SbomDependency {
    pub org: String,
    pub name: String,
    pub version: String,
    pub is_direct: bool,
    pub scope: Option<String>,
}

impl SbomDependency {
    pub fn coord(&self) -> String {
        format!("{}:{}", self.org, self.name)
    }

    pub fn purl(&self) -> String {
        // Package URL spec: pkg:maven/group/artifact@version
        let group = self.org.replace('.', "/");
        format!("pkg:maven/{}/{}@{}", group, self.name, self.version)
    }

    pub fn bom_ref(&self) -> String {
        format!("{}:{}:{}", self.org, self.name, self.version)
    }
}

/// Vulnerability data to embed in SBOM
#[derive(Debug, Clone)]
pub struct SbomVulnerability {
    pub id: String,
    pub description: String,
    pub severity: String,
    pub affected_coord: String,
    pub fix_suggestion: Option<String>,
}

/// License info to embed in SBOM
#[derive(Debug, Clone)]
pub struct SbomLicenseInfo {
    pub coord: String,
    pub license_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SbomFormat {
    CycloneDx,
    Spdx,
}

impl SbomFormat {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "cyclonedx" | "cdx" => Some(SbomFormat::CycloneDx),
            "spdx" => Some(SbomFormat::Spdx),
            _ => None,
        }
    }
}

/// Generate SBOM in the requested format
pub fn generate_sbom(
    format: SbomFormat,
    deps: &[SbomDependency],
    vulnerabilities: &[SbomVulnerability],
    licenses: &HashMap<String, String>, // coord -> SPDX license ID
    project_name: &str,
) -> String {
    match format {
        SbomFormat::CycloneDx => generate_cyclonedx(deps, vulnerabilities, licenses, project_name),
        SbomFormat::Spdx => generate_spdx(deps, vulnerabilities, licenses, project_name),
    }
}

fn generate_cyclonedx(
    deps: &[SbomDependency],
    vulnerabilities: &[SbomVulnerability],
    licenses: &HashMap<String, String>,
    project_name: &str,
) -> String {
    let serial = format!(
        "urn:uuid:{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        rand_u32(),
        rand_u16(),
        rand_u16(),
        rand_u16(),
        rand_u64() & 0xFFFFFFFFFFFF
    );

    let mut components: Vec<serde_json::Value> = Vec::new();
    for dep in deps {
        let mut comp = serde_json::json!({
            "type": "library",
            "bom-ref": dep.bom_ref(),
            "group": dep.org,
            "name": dep.name,
            "version": dep.version,
            "purl": dep.purl(),
            "scope": if dep.is_direct { "required" } else { "optional" },
        });

        if let Some(license_id) = licenses.get(&dep.coord()) {
            comp["licenses"] = serde_json::json!([
                {
                    "license": {
                        "id": license_id
                    }
                }
            ]);
        }

        components.push(comp);
    }

    let mut vuln_entries: Vec<serde_json::Value> = Vec::new();
    for vuln in vulnerabilities {
        vuln_entries.push(serde_json::json!({
            "id": vuln.id,
            "description": vuln.description,
            "ratings": [
                {
                    "severity": vuln.severity.to_lowercase(),
                    "method": "other"
                }
            ],
            "affects": [
                {
                    "ref": vuln.affected_coord
                }
            ],
            "recommendation": vuln.fix_suggestion.as_deref().unwrap_or("Review and upgrade")
        }));
    }

    let mut cdx = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": timestamp_now(),
            "tools": [
                {
                    "vendor": "scala-dep-scan",
                    "name": "scala-dep-scan",
                    "version": "0.1.0"
                }
            ],
            "component": {
                "type": "application",
                "name": project_name,
                "bom-ref": project_name
            }
        },
        "components": components,
    });

    if !vuln_entries.is_empty() {
        cdx["vulnerabilities"] = serde_json::json!(vuln_entries);
    }

    // Add dependency tree
    let mut dep_tree: Vec<serde_json::Value> = Vec::new();
    let direct_refs: Vec<String> = deps
        .iter()
        .filter(|d| d.is_direct)
        .map(|d| d.bom_ref())
        .collect();

    dep_tree.push(serde_json::json!({
        "ref": project_name,
        "dependsOn": direct_refs,
    }));

    for dep in deps.iter().filter(|d| d.is_direct) {
        dep_tree.push(serde_json::json!({
            "ref": dep.bom_ref(),
            "dependsOn": [],
        }));
    }

    cdx["dependencies"] = serde_json::json!(dep_tree);

    serde_json::to_string_pretty(&cdx).unwrap_or_else(|_| "{}".to_string())
}

fn generate_spdx(
    deps: &[SbomDependency],
    vulnerabilities: &[SbomVulnerability],
    licenses: &HashMap<String, String>,
    project_name: &str,
) -> String {
    let doc_namespace = format!(
        "https://spdx.org/spdxdocs/{}-{:08x}",
        project_name,
        rand_u32()
    );

    let mut packages: Vec<serde_json::Value> = Vec::new();
    let mut relationships: Vec<serde_json::Value> = Vec::new();

    // Root package
    let root_spdxid = "SPDXRef-RootPackage";
    packages.push(serde_json::json!({
        "SPDXID": root_spdxid,
        "name": project_name,
        "versionInfo": "0.0.0",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": false,
        "supplier": "NOASSERTION",
    }));

    relationships.push(serde_json::json!({
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relatedSpdxElement": root_spdxid,
        "relationshipType": "DESCRIBES"
    }));

    for (i, dep) in deps.iter().enumerate() {
        let spdxid = format!("SPDXRef-Package-{}", i);

        let license_concluded = licenses
            .get(&dep.coord())
            .cloned()
            .unwrap_or_else(|| "NOASSERTION".to_string());

        let mut pkg = serde_json::json!({
            "SPDXID": spdxid,
            "name": format!("{}:{}", dep.org, dep.name),
            "versionInfo": dep.version,
            "downloadLocation": format!(
                "https://repo1.maven.org/maven2/{}/{}/{}/{}-{}.jar",
                dep.org.replace('.', "/"), dep.name, dep.version, dep.name, dep.version
            ),
            "filesAnalyzed": false,
            "supplier": format!("Organization: {}", dep.org),
            "licenseConcluded": license_concluded,
            "licenseDeclared": license_concluded,
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": dep.purl()
                }
            ]
        });

        // Add security refs for vulns
        let dep_vulns: Vec<&SbomVulnerability> = vulnerabilities
            .iter()
            .filter(|v| v.affected_coord == dep.coord() || v.affected_coord == dep.bom_ref())
            .collect();

        if !dep_vulns.is_empty() {
            let mut ext_refs: Vec<serde_json::Value> = vec![serde_json::json!({
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": dep.purl()
            })];
            for v in &dep_vulns {
                ext_refs.push(serde_json::json!({
                    "referenceCategory": "SECURITY",
                    "referenceType": "advisory",
                    "referenceLocator": format!("https://osv.dev/vulnerability/{}", v.id),
                    "comment": v.description
                }));
            }
            pkg["externalRefs"] = serde_json::json!(ext_refs);
        }

        packages.push(pkg);

        if dep.is_direct {
            relationships.push(serde_json::json!({
                "spdxElementId": root_spdxid,
                "relatedSpdxElement": spdxid,
                "relationshipType": "DEPENDS_ON"
            }));
        }
    }

    let spdx = serde_json::json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": project_name,
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "created": timestamp_now(),
            "creators": ["Tool: scala-dep-scan-0.1.0"],
            "licenseListVersion": "3.22"
        },
        "packages": packages,
        "relationships": relationships,
    });

    serde_json::to_string_pretty(&spdx).unwrap_or_else(|_| "{}".to_string())
}

/// Write SBOM to file; returns Ok with path written or error message
pub fn write_sbom_to_file(content: &str, output_path: &str) -> Result<String, String> {
    std::fs::write(output_path, content)
        .map(|_| output_path.to_string())
        .map_err(|e| format!("Failed to write SBOM to {}: {}", output_path, e))
}

// Simple pseudo-random helpers (no external dep needed)
fn rand_u32() -> u32 {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    (t.as_nanos() as u32).wrapping_mul(2654435761)
}

fn rand_u16() -> u16 {
    (rand_u32() >> 8) as u16
}

fn rand_u64() -> u64 {
    let a = rand_u32() as u64;
    let b = rand_u32().wrapping_add(17) as u64;
    (a << 32) | b
}

fn timestamp_now() -> String {
    // ISO 8601 timestamp without chrono crate
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();

    // Calculate date/time from epoch seconds
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Simple year/month/day calculation from days since epoch
    let (year, month, day) = days_to_date(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

fn days_to_date(days_since_epoch: u64) -> (u64, u64, u64) {
    // Algorithm from Howard Hinnant
    let z = days_since_epoch + 719468;
    let era = z / 146097;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_purl_generation() {
        let dep = SbomDependency {
            org: "com.typesafe.play".to_string(),
            name: "play-json_2.13".to_string(),
            version: "2.9.4".to_string(),
            is_direct: true,
            scope: None,
        };
        assert_eq!(
            dep.purl(),
            "pkg:maven/com/typesafe/play/play-json_2.13@2.9.4"
        );
    }

    #[test]
    fn test_cyclonedx_structure() {
        let deps = vec![SbomDependency {
            org: "org.example".to_string(),
            name: "lib".to_string(),
            version: "1.0.0".to_string(),
            is_direct: true,
            scope: None,
        }];
        let json = generate_sbom(
            SbomFormat::CycloneDx,
            &deps,
            &[],
            &HashMap::new(),
            "test-project",
        );
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["bomFormat"], "CycloneDX");
        assert_eq!(parsed["specVersion"], "1.5");
        assert_eq!(parsed["components"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_spdx_structure() {
        let deps = vec![SbomDependency {
            org: "org.example".to_string(),
            name: "lib".to_string(),
            version: "1.0.0".to_string(),
            is_direct: true,
            scope: None,
        }];
        let json = generate_sbom(
            SbomFormat::Spdx,
            &deps,
            &[],
            &HashMap::new(),
            "test-project",
        );
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["spdxVersion"], "SPDX-2.3");
        // root + 1 dep = 2 packages
        assert_eq!(parsed["packages"].as_array().unwrap().len(), 2);
    }
}
