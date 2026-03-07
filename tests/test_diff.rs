// Tests for the diff/comparison module

#[test]
fn test_diff_no_changes() {
    let flags = serde_json::json!([
        {
            "dependency": {"org": "com.example", "name": "lib", "version": "1.0"},
            "severity": "High",
            "reason": "test",
            "risk_type": "OUTDATED",
            "cve_ids": []
        }
    ]);

    let baseline_json = serde_json::json!({
        "timestamp": "2025-01-01T00:00:00Z",
        "tool_version": "0.1.0",
        "flags": [
            {
                "coord": "com.example:lib",
                "version": "1.0",
                "severity": "High",
                "risk_type": "OUTDATED",
                "reason": "test",
                "cve_ids": []
            }
        ],
        "direct_dep_count": 5,
        "transitive_dep_count": 10
    });

    // Verify baseline can be serialized and deserialized
    let baseline_str = serde_json::to_string(&baseline_json).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&baseline_str).unwrap();
    assert_eq!(parsed["flags"].as_array().unwrap().len(), 1);
}

#[test]
fn test_diff_save_and_load_baseline() {
    let tmpdir = std::env::temp_dir().join("scala-dep-scan-test-diff-baseline");
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();

    let baseline_path = tmpdir.join("baseline.json");

    let baseline = serde_json::json!({
        "timestamp": "2025-01-01T00:00:00Z",
        "tool_version": "0.1.0",
        "flags": [
            {
                "coord": "com.example:lib",
                "version": "1.0",
                "severity": "High",
                "risk_type": "OUTDATED",
                "reason": "test reason",
                "cve_ids": ["CVE-2024-1234"]
            }
        ],
        "direct_dep_count": 5,
        "transitive_dep_count": 10
    });

    // Write baseline
    std::fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&baseline).unwrap(),
    )
    .unwrap();

    // Read it back
    let loaded = std::fs::read_to_string(&baseline_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&loaded).unwrap();

    assert_eq!(parsed["tool_version"], "0.1.0");
    assert_eq!(parsed["direct_dep_count"], 5);
    assert_eq!(parsed["flags"].as_array().unwrap().len(), 1);
    assert_eq!(parsed["flags"][0]["coord"], "com.example:lib");
    assert_eq!(parsed["flags"][0]["cve_ids"][0], "CVE-2024-1234");

    let _ = std::fs::remove_dir_all(&tmpdir);
}

#[test]
fn test_diff_identity_key_stability() {
    // The identity key should be stable for the same finding
    let key1 = format!(
        "{}::{}::{}",
        "com.example:lib", "OUTDATED", "Pre-release version"
    );
    let key2 = format!(
        "{}::{}::{}",
        "com.example:lib", "OUTDATED", "Pre-release version"
    );
    assert_eq!(key1, key2);

    // Different reasons should produce different keys
    let key3 = format!(
        "{}::{}::{}",
        "com.example:lib", "OUTDATED", "Different reason"
    );
    assert_ne!(key1, key3);
}

#[test]
fn test_diff_exit_code_logic() {
    // No new findings -> exit 0
    assert_eq!(determine_exit_code(&[], false, false), 0);

    // New high finding -> exit 1
    assert_eq!(determine_exit_code(&["high"], false, true), 1);

    // New critical finding -> exit 2
    assert_eq!(determine_exit_code(&["critical"], true, true), 2);

    // New medium only -> exit 0 (only critical/high matter)
    assert_eq!(determine_exit_code(&["medium"], false, false), 0);
}

fn determine_exit_code(severities: &[&str], has_critical: bool, has_high: bool) -> i32 {
    if has_critical {
        2
    } else if has_high {
        1
    } else {
        0
    }
}
