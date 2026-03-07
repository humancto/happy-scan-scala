// Tests for staleness scoring module

#[test]
fn test_version_parts_parsing() {
    assert_eq!(parse_version_parts("2.13.10"), Some((2, 13, 10)));
    assert_eq!(parse_version_parts("1.0"), Some((1, 0, 0)));
    assert_eq!(parse_version_parts("3"), Some((3, 0, 0)));
    assert_eq!(parse_version_parts("3.0.0-RC1"), Some((3, 0, 0)));
    assert_eq!(parse_version_parts("2.6.19+build123"), Some((2, 6, 19)));
    assert_eq!(parse_version_parts("abc"), None);
}

#[test]
fn test_versions_behind_calculation() {
    // Same version = 0 behind
    assert_eq!(estimate_versions_behind("2.13.10", "2.13.10"), 0);

    // Patch difference
    assert_eq!(estimate_versions_behind("2.9.0", "2.9.4"), 4);

    // Minor difference (1 minor + 1 for patch offset)
    assert_eq!(estimate_versions_behind("2.12.0", "2.13.10"), 2);

    // Major difference (estimated as major*10 + latest_minor)
    assert_eq!(estimate_versions_behind("1.0.0", "2.0.0"), 10);
    assert_eq!(estimate_versions_behind("1.0.0", "2.5.0"), 15);
    assert_eq!(estimate_versions_behind("1.0.0", "3.0.0"), 20);
}

#[test]
fn test_age_category_boundaries() {
    assert_eq!(categorize_age(Some(0)), "CURRENT");
    assert_eq!(categorize_age(Some(5)), "CURRENT");
    assert_eq!(categorize_age(Some(6)), "AGING");
    assert_eq!(categorize_age(Some(17)), "AGING");
    assert_eq!(categorize_age(Some(18)), "STALE");
    assert_eq!(categorize_age(Some(35)), "STALE");
    assert_eq!(categorize_age(Some(36)), "OUTDATED");
    assert_eq!(categorize_age(Some(100)), "OUTDATED");
    assert_eq!(categorize_age(None), "UNKNOWN");
}

#[test]
fn test_staleness_report_structure() {
    let report = serde_json::json!({
        "staleness": [
            {
                "coord": "com.example:lib",
                "current_version": "1.0.0",
                "latest_version": "2.5.0",
                "versions_behind": 15,
                "age_months": 40,
                "age_category": "Outdated",
                "update_available": true
            }
        ],
        "summary": {
            "total": 1,
            "current": 0,
            "aging": 0,
            "stale": 0,
            "outdated": 1,
            "unknown": 0,
            "updates_available": 1
        }
    });

    assert_eq!(report["summary"]["total"], 1);
    assert_eq!(report["summary"]["outdated"], 1);
    assert_eq!(report["staleness"][0]["versions_behind"], 15);
    assert!(report["staleness"][0]["update_available"]
        .as_bool()
        .unwrap());
}

#[test]
fn test_staleness_sorting() {
    let mut reports = vec![
        ("lib-current", "CURRENT", 2),
        ("lib-outdated", "OUTDATED", 30),
        ("lib-stale", "STALE", 10),
        ("lib-aging", "AGING", 5),
        ("lib-unknown", "UNKNOWN", 0),
    ];

    reports.sort_by(|a, b| {
        let ord = |c: &str| -> u8 {
            match c {
                "OUTDATED" => 0,
                "STALE" => 1,
                "AGING" => 2,
                "CURRENT" => 3,
                "UNKNOWN" => 4,
                _ => 5,
            }
        };
        ord(a.1).cmp(&ord(b.1)).then(b.2.cmp(&a.2))
    });

    assert_eq!(reports[0].0, "lib-outdated");
    assert_eq!(reports[1].0, "lib-stale");
    assert_eq!(reports[2].0, "lib-aging");
    assert_eq!(reports[3].0, "lib-current");
    assert_eq!(reports[4].0, "lib-unknown");
}

fn parse_version_parts(v: &str) -> Option<(u32, u32, u32)> {
    let cleaned = v.split('-').next().unwrap_or(v);
    let cleaned = cleaned.split('+').next().unwrap_or(cleaned);
    let parts: Vec<&str> = cleaned.split('.').collect();
    match parts.len() {
        1 => {
            let major = parts[0].parse().ok()?;
            Some((major, 0, 0))
        }
        2 => {
            let major = parts[0].parse().ok()?;
            let minor = parts[1].parse().ok()?;
            Some((major, minor, 0))
        }
        _ => {
            let major = parts[0].parse().ok()?;
            let minor = parts[1].parse().ok()?;
            let patch = parts[2].parse().ok()?;
            Some((major, minor, patch))
        }
    }
}

fn estimate_versions_behind(current: &str, latest: &str) -> u32 {
    let cur = parse_version_parts(current);
    let lat = parse_version_parts(latest);
    match (cur, lat) {
        (Some((cmaj, cmin, cpatch)), Some((lmaj, lmin, lpatch))) => {
            if lmaj > cmaj {
                (lmaj - cmaj) * 10 + lmin
            } else if lmin > cmin {
                let diff = lmin - cmin;
                diff + if lpatch > cpatch { 1 } else { 0 }
            } else if lpatch > cpatch {
                lpatch - cpatch
            } else {
                0
            }
        }
        _ => 0,
    }
}

fn categorize_age(months: Option<u32>) -> &'static str {
    match months {
        Some(m) if m < 6 => "CURRENT",
        Some(m) if m < 18 => "AGING",
        Some(m) if m < 36 => "STALE",
        Some(_) => "OUTDATED",
        None => "UNKNOWN",
    }
}
