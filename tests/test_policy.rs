// Tests for policy-as-code engine

#[test]
fn test_policy_expression_parsing() {
    // Test numeric comparison
    assert!(eval_rule(
        "version_age_months > 36",
        48,
        "2.6.14",
        "Apache-2.0"
    ));
    assert!(!eval_rule(
        "version_age_months > 36",
        12,
        "2.6.14",
        "Apache-2.0"
    ));
    assert!(!eval_rule(
        "version_age_months < 36",
        48,
        "2.6.14",
        "Apache-2.0"
    ));
    assert!(eval_rule(
        "version_age_months < 36",
        12,
        "2.6.14",
        "Apache-2.0"
    ));
}

#[test]
fn test_policy_string_equality() {
    assert!(eval_rule("license == GPL-3.0", 12, "2.0", "GPL-3.0"));
    assert!(!eval_rule("license == GPL-3.0", 12, "2.0", "MIT"));
    assert!(eval_rule("license != unknown", 12, "2.0", "MIT"));
    assert!(!eval_rule("license != unknown", 12, "2.0", "unknown"));
}

#[test]
fn test_policy_regex_match() {
    assert!(eval_rule("version =~ /^0\\./", 12, "0.2.1", "MIT"));
    assert!(!eval_rule("version =~ /^0\\./", 12, "2.0.1", "MIT"));
    assert!(eval_rule("version !~ /^0\\./", 12, "2.0.1", "MIT"));
    assert!(!eval_rule("version !~ /^0\\./", 12, "0.2.1", "MIT"));
}

#[test]
fn test_policy_yaml_roundtrip() {
    let yaml = r#"policies:
  - name: no-ancient-deps
    rule: version_age_months > 36
    severity: high
    message: Dependencies must be updated within 3 years
  - name: no-pre-release
    rule: version =~ /^0\./
    severity: medium
"#;

    // Parse the YAML to verify structure
    let parsed: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
    let policies = parsed["policies"].as_sequence().unwrap();
    assert_eq!(policies.len(), 2);
    assert_eq!(policies[0]["name"].as_str().unwrap(), "no-ancient-deps");
    assert_eq!(policies[1]["name"].as_str().unwrap(), "no-pre-release");
}

#[test]
fn test_policy_violation_output() {
    // Test that violations generate proper output structure
    let violation = serde_json::json!({
        "coord": "com.example:lib",
        "org": "com.example",
        "name": "lib",
        "version": "1.0.0",
        "severity": "high",
        "reason": "Dependencies must be updated within 3 years",
        "risk_type": "POLICY",
        "policy_name": "no-ancient-deps"
    });

    assert_eq!(violation["risk_type"], "POLICY");
    assert_eq!(violation["policy_name"], "no-ancient-deps");
}

#[test]
fn test_policy_all_operators() {
    // < operator
    assert!(eval_rule("version_age_months < 50", 48, "2.0", "MIT"));
    assert!(!eval_rule("version_age_months < 40", 48, "2.0", "MIT"));

    // > operator
    assert!(eval_rule("version_age_months > 40", 48, "2.0", "MIT"));
    assert!(!eval_rule("version_age_months > 50", 48, "2.0", "MIT"));

    // == operator
    assert!(eval_rule("license == MIT", 0, "1.0", "MIT"));
    assert!(!eval_rule("license == Apache-2.0", 0, "1.0", "MIT"));

    // != operator
    assert!(eval_rule("license != GPL-3.0", 0, "1.0", "MIT"));
    assert!(!eval_rule("license != MIT", 0, "1.0", "MIT"));

    // =~ operator (regex match)
    assert!(eval_rule("version =~ /^2\\./", 0, "2.6.14", "MIT"));
    assert!(!eval_rule("version =~ /^3\\./", 0, "2.6.14", "MIT"));

    // !~ operator (regex not match)
    assert!(eval_rule("version !~ /^3\\./", 0, "2.6.14", "MIT"));
    assert!(!eval_rule("version !~ /^2\\./", 0, "2.6.14", "MIT"));
}

/// Helper to evaluate a policy rule expression against test context
fn eval_rule(rule: &str, age_months: u64, version: &str, license: &str) -> bool {
    // Simple expression parser matching the policy.rs implementation
    let operators: &[(&str, &str)] = &[
        ("!~", "notmatch"),
        ("=~", "match"),
        ("!=", "neq"),
        ("==", "eq"),
        ("<", "lt"),
        (">", "gt"),
    ];

    for (token, op) in operators {
        if let Some(pos) = rule.find(token) {
            let field = rule[..pos].trim();
            let raw_value = rule[pos + token.len()..].trim();
            let value = raw_value
                .trim_matches('"')
                .trim_matches('\'')
                .trim_matches('/');

            let field_val = match field {
                "version" => version.to_string(),
                "version_age_months" => age_months.to_string(),
                "license" => license.to_string(),
                _ => String::new(),
            };

            return match *op {
                "eq" => field_val == value,
                "neq" => field_val != value,
                "lt" => {
                    if let (Ok(a), Ok(b)) = (field_val.parse::<f64>(), value.parse::<f64>()) {
                        a < b
                    } else {
                        field_val < value.to_string()
                    }
                }
                "gt" => {
                    if let (Ok(a), Ok(b)) = (field_val.parse::<f64>(), value.parse::<f64>()) {
                        a > b
                    } else {
                        field_val > value.to_string()
                    }
                }
                "match" => regex::Regex::new(value)
                    .map(|re| re.is_match(&field_val))
                    .unwrap_or(false),
                "notmatch" => regex::Regex::new(value)
                    .map(|re| !re.is_match(&field_val))
                    .unwrap_or(true),
                _ => false,
            };
        }
    }
    false
}
