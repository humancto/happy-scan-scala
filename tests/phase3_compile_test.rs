// Integration test to verify Phase 3 modules compile and work correctly.
// These modules are self-contained and don't depend on other project modules.

#[path = "../src/policy.rs"]
mod policy;
#[path = "../src/html_report.rs"]
mod html_report;
#[path = "../src/diff.rs"]
mod diff;
#[path = "../src/ci_templates.rs"]
mod ci_templates;

#[test]
fn test_policy_engine_yaml_parsing() {
    let yaml = r#"
policies:
  - name: "no-ancient-deps"
    rule: "version_age_months > 36"
    severity: high
    message: "Dependencies must be updated within 3 years"
  - name: "no-pre-release"
    rule: "version =~ /^0\./"
    severity: medium
  - name: "require-known-license"
    rule: "license == unknown"
    severity: low
"#;
    let engine = policy::PolicyEngine::from_yaml(yaml).unwrap();
    assert_eq!(engine.policy_count(), 3);
}

#[test]
fn test_policy_evaluation() {
    let yaml = r#"
policies:
  - name: "no-ancient-deps"
    rule: "version_age_months > 36"
    severity: high
"#;
    let engine = policy::PolicyEngine::from_yaml(yaml).unwrap();
    let ctx = policy::DepContext {
        org: "com.example".to_string(),
        name: "lib".to_string(),
        version: "1.0.0".to_string(),
        coord: "com.example:lib".to_string(),
        version_age_months: Some(48),
        license: "MIT".to_string(),
        is_direct: true,
    };
    let violations = engine.evaluate(&ctx);
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].severity, "high");
}

#[test]
fn test_policy_json_evaluation() {
    let yaml = r#"
policies:
  - name: "no-pre-release"
    rule: "version =~ /^0\./"
    severity: medium
"#;
    let engine = policy::PolicyEngine::from_yaml(yaml).unwrap();
    let deps = serde_json::json!([
        {"org": "com.example", "name": "alpha-lib", "version": "0.9.1", "is_transitive": false},
        {"org": "com.example", "name": "stable-lib", "version": "2.1.0", "is_transitive": false}
    ]);
    let violations = engine.evaluate_json(&deps);
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].coord, "com.example:alpha-lib");
}

#[test]
fn test_html_report_generates_valid_html() {
    let data = serde_json::json!({
        "direct_deps": [
            {"org": "com.typesafe.play", "name": "play-json", "version": "2.6.14"}
        ],
        "transitive_deps": [],
        "risk_flags": [
            {
                "dependency": {"org": "com.typesafe.play", "name": "play-json", "version": "2.6.14"},
                "severity": "High",
                "reason": "Outdated dependency",
                "risk_type": "OUTDATED",
                "cve_ids": []
            }
        ],
        "code_refs": {},
        "usage": [
            {"coord": "com.typesafe.play:play-json", "version": "2.6.14", "verdict": "ACTIVE", "usage_count": 5, "symbols_found": ["Json", "JsValue"]}
        ],
        "graph_json": "{}"
    });
    let html = html_report::generate_html_report(&data);
    assert!(html.starts_with("<!DOCTYPE html>"));
    assert!(html.contains("play-json"));
    assert!(html.contains("Outdated dependency"));
    assert!(html.contains("Executive Summary"));
    assert!(html.contains("</html>"));
}

#[test]
fn test_diff_baseline_roundtrip() {
    let flags = serde_json::json!([
        {
            "dependency": {"org": "com.example", "name": "lib-a", "version": "1.0.0"},
            "severity": "High",
            "reason": "Old version",
            "risk_type": "OUTDATED",
            "cve_ids": []
        }
    ]);
    let path = std::path::Path::new("/tmp/scala_dep_scan_test_baseline.json");
    diff::save_baseline(path, &flags, 5, 20).unwrap();
    let baseline = diff::load_baseline(path).unwrap();
    assert_eq!(baseline.flags.len(), 1);
    assert_eq!(baseline.direct_dep_count, 5);
    assert_eq!(baseline.transitive_dep_count, 20);
    let _ = std::fs::remove_file(path);
}

#[test]
fn test_diff_comparison() {
    let old_flags = serde_json::json!([
        {
            "dependency": {"org": "com.example", "name": "lib-a", "version": "1.0.0"},
            "severity": "High",
            "reason": "Old version",
            "risk_type": "OUTDATED",
            "cve_ids": []
        }
    ]);
    let path = std::path::Path::new("/tmp/scala_dep_scan_test_baseline2.json");
    diff::save_baseline(path, &old_flags, 5, 20).unwrap();
    let baseline = diff::load_baseline(path).unwrap();

    let new_flags = serde_json::json!([
        {
            "dependency": {"org": "com.example", "name": "lib-a", "version": "1.0.0"},
            "severity": "High",
            "reason": "Old version",
            "risk_type": "OUTDATED",
            "cve_ids": []
        },
        {
            "dependency": {"org": "com.example", "name": "lib-b", "version": "0.1.0"},
            "severity": "Critical",
            "reason": "Known CVE",
            "risk_type": "KNOWN-CVE",
            "cve_ids": ["CVE-2025-99999"]
        }
    ]);
    let result = diff::compare(&baseline, &new_flags, 6, 22);
    assert_eq!(result.new_flags.len(), 1);
    assert_eq!(result.resolved_flags.len(), 0);
    assert_eq!(result.unchanged_flags.len(), 1);
    assert!(result.has_new_critical_or_high());
    assert_eq!(result.exit_code(), 2);
    let _ = std::fs::remove_file(path);
}

#[test]
fn test_ci_github_template() {
    let t = ci_templates::generate_ci_template("github");
    assert!(t.contains("name: Dependency Risk Scan"));
    assert!(t.contains("actions/checkout"));
    assert!(t.contains("scala-dep-scan"));
}

#[test]
fn test_ci_gitlab_template() {
    let t = ci_templates::generate_ci_template("gitlab");
    assert!(t.contains("stages:"));
    assert!(t.contains("dependency-risk-scan:"));
}

#[test]
fn test_ci_unsupported() {
    let t = ci_templates::generate_ci_template("circleci");
    assert!(t.contains("Error: Unsupported"));
}
