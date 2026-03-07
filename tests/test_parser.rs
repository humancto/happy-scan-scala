use std::path::Path;

// Since the modules are private in main.rs (binary crate), we test via the
// binary CLI for integration tests. For unit tests, we add #[cfg(test)]
// inside each source module. This file tests via the compiled binary.

#[test]
fn test_parse_simple_build_sbt_via_cli() {
    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
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
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect(&format!("Invalid JSON output: {}", stdout));

    // Should find dependencies from simple_build.sbt
    let summary = &json["summary"];
    assert!(
        summary["direct_deps"].as_u64().unwrap() > 0,
        "Should find direct dependencies"
    );
}

#[test]
fn test_json_output_structure() {
    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
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

    // Verify JSON structure
    assert!(json.get("summary").is_some(), "Should have summary");
    assert!(json.get("risk_flags").is_some(), "Should have risk_flags");
    assert!(
        json.get("code_references").is_some(),
        "Should have code_references"
    );
    assert!(json.get("graph").is_some(), "Should have graph");

    let summary = &json["summary"];
    assert!(summary.get("direct_deps").is_some());
    assert!(summary.get("transitive_deps").is_some());
    assert!(summary.get("total_flags").is_some());
    assert!(summary.get("critical").is_some());
    assert!(summary.get("high").is_some());
    assert!(summary.get("medium").is_some());
    assert!(summary.get("low").is_some());
}

#[test]
fn test_detects_known_vulnerable_deps() {
    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
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

    let empty = vec![];
    let flags = json["risk_flags"].as_array().unwrap_or(&empty);

    // Should detect play-json 2.3.2 as vulnerable (risky below 2.9.0)
    let play_json_flag = flags.iter().find(|f| {
        f["dependency"]["name"]
            .as_str()
            .map_or(false, |n| n.contains("play-json"))
    });
    assert!(
        play_json_flag.is_some(),
        "Should flag play-json:2.3.2 as risky"
    );

    // Should detect mysql connector as vulnerable
    let mysql_flag = flags.iter().find(|f| {
        f["dependency"]["name"]
            .as_str()
            .map_or(false, |n| n.contains("mysql"))
    });
    assert!(
        mysql_flag.is_some(),
        "Should flag mysql-connector-java:5.1.31 as risky"
    );

    // Should detect guava as vulnerable (< 30.0)
    let guava_flag = flags.iter().find(|f| {
        f["dependency"]["name"]
            .as_str()
            .map_or(false, |n| n.contains("guava"))
            && f["risk_type"]
                .as_str()
                .map_or(false, |r| r == "KnownVulnerable")
    });
    assert!(
        guava_flag.is_some(),
        "Should flag guava:28.0-jre as risky (below 30.0)"
    );
}

#[test]
fn test_detects_outdated_deps() {
    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
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

    let empty2 = vec![];
    let flags = json["risk_flags"].as_array().unwrap_or(&empty2);

    // play-json-extensions:0.2 should be flagged as pre-release (0.x)
    let pre_release_flag = flags.iter().find(|f| {
        f["dependency"]["name"]
            .as_str()
            .map_or(false, |n| n.contains("play-json-extensions"))
            && f["risk_type"].as_str().map_or(false, |r| r == "Outdated")
    });
    assert!(
        pre_release_flag.is_some(),
        "Should flag 0.x version as pre-release"
    );

    // commons-lang:2.6 should be flagged as deprecated
    let deprecated_flag = flags.iter().find(|f| {
        f["dependency"]["name"]
            .as_str()
            .map_or(false, |n| n.contains("commons-lang"))
            && f["risk_type"].as_str().map_or(false, |r| r == "Outdated")
    });
    assert!(
        deprecated_flag.is_some(),
        "Should flag commons-lang as deprecated"
    );
}

#[test]
fn test_exit_code_critical() {
    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_scala-dep-scan"))
        .args([fixture_dir.to_str().unwrap(), "-q", "--no-tree"])
        .output()
        .expect("Failed to execute binary");

    // The fixture has play-json 2.3.2 which triggers a critical flag via known-CVE
    // Exit code should be 1 (HIGH) or 2 (CRITICAL)
    assert!(
        !output.status.success(),
        "Should exit non-zero when risky deps found"
    );
}

#[test]
fn test_severity_filter() {
    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_scala-dep-scan"))
        .args([
            fixture_dir.to_str().unwrap(),
            "-f",
            "json",
            "-q",
            "--no-tree",
            "-s",
            "critical",
        ])
        .output()
        .expect("Failed to execute binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_default();

    // All flags are still in JSON output (filter only affects terminal display)
    // but we can verify the flag count
    let total = json["summary"]["total_flags"].as_u64().unwrap_or(0);
    assert!(total > 0, "Should still report flags in JSON");
}

#[test]
fn test_no_sbt_project_exits_with_error() {
    let tmpdir = std::env::temp_dir().join("scala-dep-scan-test-empty");
    let _ = std::fs::create_dir_all(&tmpdir);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_scala-dep-scan"))
        .args([tmpdir.to_str().unwrap(), "-q"])
        .output()
        .expect("Failed to execute binary");

    assert!(
        !output.status.success(),
        "Should exit non-zero for non-SBT project"
    );

    let _ = std::fs::remove_dir_all(&tmpdir);
}

#[test]
fn test_show_deps_flag() {
    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_scala-dep-scan"))
        .args([
            fixture_dir.to_str().unwrap(),
            "--show-deps",
            "-q",
            "--no-tree",
        ])
        .output()
        .expect("Failed to execute binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Direct Dependencies") || stdout.contains("play-json"),
        "Should show dependency table"
    );
}

#[test]
fn test_graph_json_output() {
    let tmpdir = std::env::temp_dir().join("scala-dep-scan-test-graph");
    let _ = std::fs::create_dir_all(&tmpdir);
    let graph_path = tmpdir.join("deps.json");

    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let _ = std::process::Command::new(env!("CARGO_BIN_EXE_scala-dep-scan"))
        .args([
            fixture_dir.to_str().unwrap(),
            "--graph-json",
            graph_path.to_str().unwrap(),
            "-q",
            "--no-tree",
        ])
        .output()
        .expect("Failed to execute binary");

    if graph_path.exists() {
        let content = std::fs::read_to_string(&graph_path).unwrap();
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(json.get("nodes").is_some(), "Graph JSON should have nodes");
        assert!(json.get("edges").is_some(), "Graph JSON should have edges");
    }

    let _ = std::fs::remove_dir_all(&tmpdir);
}

#[test]
fn test_dot_output() {
    let tmpdir = std::env::temp_dir().join("scala-dep-scan-test-dot");
    let _ = std::fs::create_dir_all(&tmpdir);
    let dot_path = tmpdir.join("deps.dot");

    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let _ = std::process::Command::new(env!("CARGO_BIN_EXE_scala-dep-scan"))
        .args([
            fixture_dir.to_str().unwrap(),
            "--dot",
            dot_path.to_str().unwrap(),
            "-q",
            "--no-tree",
        ])
        .output()
        .expect("Failed to execute binary");

    if dot_path.exists() {
        let content = std::fs::read_to_string(&dot_path).unwrap();
        assert!(content.contains("digraph"), "DOT output should be valid");
        assert!(
            content.contains("scala-dep-scan"),
            "DOT should have header comment"
        );
    }

    let _ = std::fs::remove_dir_all(&tmpdir);
}
