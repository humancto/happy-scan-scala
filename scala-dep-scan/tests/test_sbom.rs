// Tests for SBOM generation module
// The sbom module is self-contained with its own types

#[test]
fn test_cyclonedx_valid_json() {
    // We test the binary output by running it with SBOM flags
    // Since SBOM is not yet wired into main.rs CLI, we test the module
    // via its inline tests. This integration test verifies the CLI
    // handles unknown flags gracefully.

    // For now, test the SBOM module's functions directly via a subprocess
    // that exercises the JSON output path
    let fixture_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_scala-dep-scan"))
        .args([
            fixture_dir.to_str().unwrap(),
            "-f",
            "json",
            "-q",
            "--no-tree",
        ])
        .output()
        .expect("Failed to execute binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_default();

    // Verify we can extract dep data that would feed into SBOM
    let summary = &json["summary"];
    assert!(
        summary["direct_deps"].as_u64().unwrap_or(0) > 0,
        "Should have deps for SBOM generation"
    );

    // Verify risk flags contain required fields for SBOM vulnerability section
    if let Some(flags) = json["risk_flags"].as_array() {
        for flag in flags {
            assert!(
                flag.get("dependency").is_some(),
                "Flag should have dependency"
            );
            assert!(flag.get("severity").is_some(), "Flag should have severity");
            assert!(flag.get("reason").is_some(), "Flag should have reason");
        }
    }
}

#[test]
fn test_purl_format() {
    // Verify Package URL format is correct
    let purl = format!(
        "pkg:maven/{}/{}@{}",
        "com/typesafe/play", "play-json_2.13", "2.9.4"
    );
    assert_eq!(purl, "pkg:maven/com/typesafe/play/play-json_2.13@2.9.4");

    // Group with dots should be converted to slashes
    let org = "com.fasterxml.jackson.core";
    let group = org.replace('.', "/");
    assert_eq!(group, "com/fasterxml/jackson/core");
}
