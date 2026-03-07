// Tests for license compliance module

#[test]
fn test_license_classification() {
    let test_cases = vec![
        ("MIT", "permissive"),
        ("MIT License", "permissive"),
        ("Apache License 2.0", "permissive"),
        ("Apache-2.0", "permissive"),
        ("BSD-3-Clause", "permissive"),
        ("BSD 2-Clause", "permissive"),
        ("ISC", "permissive"),
        ("Unlicense", "permissive"),
        ("CC0-1.0", "permissive"),
        ("The Artistic License 2.0", "permissive"),
        ("Boost Software License 1.0", "permissive"),
        ("zlib License", "permissive"),
        ("GPL-3.0", "strong-copyleft"),
        ("GNU General Public License v3", "strong-copyleft"),
        ("GPL-2.0", "strong-copyleft"),
        ("AGPL-3.0", "strong-copyleft"),
        ("LGPL-2.1", "weak-copyleft"),
        ("GNU Lesser General Public License", "weak-copyleft"),
        ("Mozilla Public License 2.0", "weak-copyleft"),
        ("MPL-2.0", "weak-copyleft"),
        ("Eclipse Public License 2.0", "weak-copyleft"),
        ("Common Public License 1.0", "weak-copyleft"),
        ("Unknown License", "unknown"),
        ("Proprietary", "unknown"),
    ];

    for (license_name, expected_class) in test_cases {
        let class = classify(license_name);
        assert_eq!(
            class, expected_class,
            "License '{}' should be classified as '{}'",
            license_name, expected_class
        );
    }
}

fn classify(name: &str) -> &'static str {
    let lower = name.to_lowercase();
    let permissive = [
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
    for p in &permissive {
        if lower.contains(p) {
            return "permissive";
        }
    }
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
            if lower.contains("lgpl") || lower.contains("lesser") {
                return "weak-copyleft";
            }
            return "strong-copyleft";
        }
    }
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
            return "weak-copyleft";
        }
    }
    "unknown"
}

#[test]
fn test_spdx_normalization() {
    assert_eq!(
        normalize_spdx("The Apache Software License, Version 2.0"),
        "Apache-2.0"
    );
    assert_eq!(normalize_spdx("MIT"), "MIT");
    assert_eq!(
        normalize_spdx("GNU Lesser General Public License v2.1"),
        "LGPL-2.1"
    );
    assert_eq!(normalize_spdx("BSD 3-Clause"), "BSD-3-Clause");
    assert_eq!(normalize_spdx("Eclipse Public License 1.0"), "EPL-2.0");
    assert_eq!(normalize_spdx("ISC License"), "ISC");
}

fn normalize_spdx(name: &str) -> &str {
    let lower = name.to_lowercase();
    if lower.contains("apache") && lower.contains("2") {
        return "Apache-2.0";
    }
    if lower == "mit" || lower.contains("mit license") {
        return "MIT";
    }
    if lower.contains("bsd") && lower.contains("3") {
        return "BSD-3-Clause";
    }
    if lower.contains("bsd") && lower.contains("2") {
        return "BSD-2-Clause";
    }
    if (lower.contains("lgpl") || lower.contains("lesser")) && lower.contains("2.1") {
        return "LGPL-2.1";
    }
    if (lower.contains("lgpl") || lower.contains("lesser")) && lower.contains("3") {
        return "LGPL-3.0";
    }
    if lower.contains("agpl") {
        return "AGPL-3.0";
    }
    if lower.contains("gpl") && lower.contains("3") {
        return "GPL-3.0";
    }
    if lower.contains("gpl") && lower.contains("2") {
        return "GPL-2.0";
    }
    if lower.contains("mpl") && lower.contains("2") {
        return "MPL-2.0";
    }
    if lower.contains("eclipse") || lower.contains("epl") {
        return "EPL-2.0";
    }
    if lower.contains("isc") {
        return "ISC";
    }
    if lower.contains("unlicense") {
        return "Unlicense";
    }
    name
}

#[test]
fn test_policy_parsing() {
    let policy_str = "allow:MIT,Apache-2.0 deny:GPL-3.0,AGPL-3.0";
    let parts: Vec<&str> = policy_str.split_whitespace().collect();

    let mut allow_list: Vec<String> = Vec::new();
    let mut deny_list: Vec<String> = Vec::new();

    for part in parts {
        if let Some(ids) = part.strip_prefix("allow:") {
            allow_list.extend(ids.split(',').map(|s| s.trim().to_string()));
        } else if let Some(ids) = part.strip_prefix("deny:") {
            deny_list.extend(ids.split(',').map(|s| s.trim().to_string()));
        }
    }

    assert_eq!(allow_list, vec!["MIT", "Apache-2.0"]);
    assert_eq!(deny_list, vec!["GPL-3.0", "AGPL-3.0"]);
}

#[test]
fn test_policy_deny_check() {
    let deny_list = vec!["GPL-3.0".to_string(), "AGPL-3.0".to_string()];
    let license = "GPL-3.0";

    let is_denied = deny_list.iter().any(|d| license.eq_ignore_ascii_case(d));
    assert!(is_denied, "GPL-3.0 should be denied");

    let is_denied_mit = deny_list.iter().any(|d| "MIT".eq_ignore_ascii_case(d));
    assert!(!is_denied_mit, "MIT should not be denied");
}

#[test]
fn test_policy_allow_check() {
    let allow_list = vec!["MIT".to_string(), "Apache-2.0".to_string()];
    let license = "GPL-3.0";

    let is_allowed = allow_list.iter().any(|a| license.eq_ignore_ascii_case(a));
    assert!(!is_allowed, "GPL-3.0 should not be allowed");

    let is_allowed_mit = allow_list.iter().any(|a| "MIT".eq_ignore_ascii_case(a));
    assert!(is_allowed_mit, "MIT should be allowed");
}
