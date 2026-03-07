//! Policy-as-Code Engine
//!
//! Loads policy rules from YAML files and evaluates them against dependencies
//! to produce policy violation flags. Designed to be self-contained — does not
//! import from other project modules.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

// ── Local type mirrors (avoids touching types.rs) ───────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRiskFlag {
    pub coord: String,
    pub org: String,
    pub name: String,
    pub version: String,
    pub severity: String,
    pub reason: String,
    pub risk_type: String,
    pub policy_name: String,
}

// ── Policy definition ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    pub rule: String,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default)]
    pub message: Option<String>,
}

fn default_severity() -> String {
    "medium".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyFile {
    pub policies: Vec<Policy>,
}

// ── Dependency context for evaluation ───────────────────────────────────────

/// A flattened view of a dependency used for policy evaluation.
/// Callers build this from their own Dependency type.
#[derive(Debug, Clone)]
pub struct DepContext {
    pub org: String,
    pub name: String,
    pub version: String,
    pub coord: String,
    pub version_age_months: Option<u64>,
    pub license: String,
    pub is_direct: bool,
}

impl DepContext {
    /// Create from a serde_json::Value that represents a dependency object.
    /// Expected keys: org, name, version, is_transitive (bool), and optional
    /// version_age_months, license.
    pub fn from_json(v: &serde_json::Value) -> Option<Self> {
        let org = v.get("org")?.as_str()?.to_string();
        let name = v.get("name")?.as_str()?.to_string();
        let version = v.get("version")?.as_str()?.to_string();
        let coord = format!("{}:{}", org, name);
        let is_transitive = v
            .get("is_transitive")
            .and_then(|b| b.as_bool())
            .unwrap_or(false);
        let version_age_months = v.get("version_age_months").and_then(|n| n.as_u64());
        let license = v
            .get("license")
            .and_then(|l| l.as_str())
            .unwrap_or("unknown")
            .to_string();
        Some(DepContext {
            org,
            name,
            version,
            coord,
            version_age_months,
            license,
            is_direct: !is_transitive,
        })
    }
}

// ── Expression evaluator ────────────────────────────────────────────────────

/// Supported operators
#[derive(Debug)]
enum Op {
    Lt,       // <
    Gt,       // >
    Eq,       // ==
    Neq,      // !=
    Match,    // =~
    NotMatch, // !~
}

#[derive(Debug)]
struct Expr {
    field: String,
    op: Op,
    value: String,
}

fn parse_expr(rule: &str) -> Option<Expr> {
    // Order matters — check two-char operators before one-char ones
    let operators: &[(&str, Op)] = &[
        ("!~", Op::NotMatch),
        ("=~", Op::Match),
        ("!=", Op::Neq),
        ("==", Op::Eq),
        ("<=", Op::Lt), // treat <= as Lt for simplicity (inclusive)
        (">=", Op::Gt),
        ("<", Op::Lt),
        (">", Op::Gt),
    ];

    for (token, _op_variant) in operators {
        if let Some(pos) = rule.find(token) {
            let field = rule[..pos].trim().to_string();
            let raw_value = rule[pos + token.len()..].trim().to_string();
            // Strip surrounding quotes or regex delimiters /…/
            let value = raw_value
                .trim_matches('"')
                .trim_matches('\'')
                .trim_matches('/')
                .to_string();
            let op = match token {
                &"!~" => Op::NotMatch,
                &"=~" => Op::Match,
                &"!=" => Op::Neq,
                &"==" => Op::Eq,
                &"<" | &"<=" => Op::Lt,
                &">" | &">=" => Op::Gt,
                _ => return None,
            };
            return Some(Expr { field, op, value });
        }
    }
    None
}

fn resolve_field(ctx: &DepContext, field: &str) -> String {
    match field {
        "version" => ctx.version.clone(),
        "org" => ctx.org.clone(),
        "name" => ctx.name.clone(),
        "coord" => ctx.coord.clone(),
        "version_age_months" => ctx
            .version_age_months
            .map(|v| v.to_string())
            .unwrap_or_else(|| "0".to_string()),
        "license" => ctx.license.clone(),
        "is_direct" => {
            if ctx.is_direct {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        _ => String::new(),
    }
}

fn evaluate(expr: &Expr, ctx: &DepContext) -> bool {
    let field_val = resolve_field(ctx, &expr.field);

    match expr.op {
        Op::Eq => field_val == expr.value,
        Op::Neq => field_val != expr.value,
        Op::Lt => {
            if let (Ok(a), Ok(b)) = (field_val.parse::<f64>(), expr.value.parse::<f64>()) {
                a < b
            } else {
                field_val < expr.value
            }
        }
        Op::Gt => {
            if let (Ok(a), Ok(b)) = (field_val.parse::<f64>(), expr.value.parse::<f64>()) {
                a > b
            } else {
                field_val > expr.value
            }
        }
        Op::Match => Regex::new(&expr.value)
            .map(|re| re.is_match(&field_val))
            .unwrap_or(false),
        Op::NotMatch => Regex::new(&expr.value)
            .map(|re| !re.is_match(&field_val))
            .unwrap_or(true),
    }
}

// ── PolicyEngine ────────────────────────────────────────────────────────────

pub struct PolicyEngine {
    policies: Vec<Policy>,
}

impl PolicyEngine {
    /// Load policies from a YAML file. Returns an empty engine if the file
    /// doesn't exist.
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(PolicyEngine {
                policies: Vec::new(),
            });
        }
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read policy file {}: {}", path.display(), e))?;
        Self::from_yaml(&content)
    }

    /// Parse policies from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, String> {
        // We do a minimal YAML parser since we can't add `serde_yaml` to
        // Cargo.toml. We parse a simple subset:
        //   policies:
        //     - name: "..."
        //       rule: "..."
        //       severity: high
        //       message: "..."
        let policies = Self::parse_policies_yaml(yaml)?;
        Ok(PolicyEngine { policies })
    }

    /// Evaluate all policies against one dependency context.
    /// Returns violations (i.e., where the rule expression is TRUE,
    /// meaning the dependency violates the policy).
    pub fn evaluate(&self, ctx: &DepContext) -> Vec<PolicyRiskFlag> {
        let mut violations = Vec::new();
        for policy in &self.policies {
            if let Some(expr) = parse_expr(&policy.rule) {
                if evaluate(&expr, ctx) {
                    let message = policy.message.clone().unwrap_or_else(|| {
                        format!(
                            "Policy '{}' violated: {} for {}",
                            policy.name, policy.rule, ctx.coord
                        )
                    });
                    violations.push(PolicyRiskFlag {
                        coord: ctx.coord.clone(),
                        org: ctx.org.clone(),
                        name: ctx.name.clone(),
                        version: ctx.version.clone(),
                        severity: policy.severity.clone(),
                        reason: message,
                        risk_type: "POLICY".to_string(),
                        policy_name: policy.name.clone(),
                    });
                }
            }
        }
        violations
    }

    /// Evaluate policies against a JSON array of dependency objects.
    pub fn evaluate_json(&self, deps_json: &serde_json::Value) -> Vec<PolicyRiskFlag> {
        let mut all_violations = Vec::new();
        if let Some(arr) = deps_json.as_array() {
            for dep_val in arr {
                if let Some(ctx) = DepContext::from_json(dep_val) {
                    all_violations.extend(self.evaluate(&ctx));
                }
            }
        }
        all_violations
    }

    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    // ── Minimal YAML parser ─────────────────────────────────────────────

    fn parse_policies_yaml(yaml: &str) -> Result<Vec<Policy>, String> {
        let mut policies: Vec<Policy> = Vec::new();
        let mut current: Option<HashMap<String, String>> = None;

        let mut in_policies_block = false;

        for line in yaml.lines() {
            let trimmed = line.trim();

            // Skip empty lines and comments
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if trimmed == "policies:" {
                in_policies_block = true;
                continue;
            }

            if !in_policies_block {
                continue;
            }

            // New list item
            if trimmed.starts_with("- ") {
                // Save previous
                if let Some(map) = current.take() {
                    if let Some(p) = Self::map_to_policy(&map) {
                        policies.push(p);
                    }
                }
                current = Some(HashMap::new());
                // Parse inline key: value after "- "
                let kv = trimmed.trim_start_matches("- ");
                if let Some((k, v)) = Self::parse_kv(kv) {
                    if let Some(ref mut m) = current {
                        m.insert(k, v);
                    }
                }
                continue;
            }

            // Continuation key: value
            if let Some(ref mut map) = current {
                if let Some((k, v)) = Self::parse_kv(trimmed) {
                    map.insert(k, v);
                }
            }
        }

        // Flush last
        if let Some(map) = current.take() {
            if let Some(p) = Self::map_to_policy(&map) {
                policies.push(p);
            }
        }

        Ok(policies)
    }

    fn parse_kv(s: &str) -> Option<(String, String)> {
        let colon = s.find(':')?;
        let key = s[..colon].trim().to_string();
        let val = s[colon + 1..]
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();
        Some((key, val))
    }

    fn map_to_policy(map: &HashMap<String, String>) -> Option<Policy> {
        let name = map.get("name")?.clone();
        let rule = map.get("rule")?.clone();
        let severity = map
            .get("severity")
            .cloned()
            .unwrap_or_else(|| "medium".to_string());
        let message = map.get("message").cloned();
        Some(Policy {
            name,
            rule,
            severity,
            message,
        })
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ctx() -> DepContext {
        DepContext {
            org: "com.typesafe.play".to_string(),
            name: "play-json".to_string(),
            version: "2.6.14".to_string(),
            coord: "com.typesafe.play:play-json".to_string(),
            version_age_months: Some(48),
            license: "Apache-2.0".to_string(),
            is_direct: true,
        }
    }

    #[test]
    fn test_numeric_lt() {
        let expr = parse_expr("version_age_months < 36").unwrap();
        let ctx = sample_ctx();
        // 48 < 36 => false, so policy NOT violated
        assert!(!evaluate(&expr, &ctx));
    }

    #[test]
    fn test_numeric_gt() {
        let expr = parse_expr("version_age_months > 36").unwrap();
        let ctx = sample_ctx();
        // 48 > 36 => true
        assert!(evaluate(&expr, &ctx));
    }

    #[test]
    fn test_regex_match() {
        let expr = parse_expr("version =~ /^2\\./").unwrap();
        let ctx = sample_ctx();
        assert!(evaluate(&expr, &ctx));
    }

    #[test]
    fn test_regex_not_match() {
        let expr = parse_expr("version !~ /^0\\./").unwrap();
        let ctx = sample_ctx();
        assert!(evaluate(&expr, &ctx));
    }

    #[test]
    fn test_neq() {
        let expr = parse_expr("license != unknown").unwrap();
        let ctx = sample_ctx();
        assert!(evaluate(&expr, &ctx));
    }

    #[test]
    fn test_policy_yaml_parsing() {
        let yaml = r#"
policies:
  - name: "no-ancient-deps"
    rule: "version_age_months > 36"
    severity: high
    message: "Dependencies must be updated within 3 years"
  - name: "no-pre-release"
    rule: "version =~ /^0\\./"
    severity: medium
"#;
        let engine = PolicyEngine::from_yaml(yaml).unwrap();
        assert_eq!(engine.policy_count(), 2);

        let ctx = sample_ctx();
        let violations = engine.evaluate(&ctx);
        // version_age_months=48 > 36 => violated
        // version=2.6.14 matches ^0\. => false => not violated
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].policy_name, "no-ancient-deps");
    }
}
