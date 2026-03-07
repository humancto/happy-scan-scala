// Upgrade Path Advisor module
// Curated migration guide database with effort estimation.
// Self-contained — no imports from other crate modules.

use serde::{Deserialize, Serialize};

/// A curated migration guide for a specific upgrade path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationGuide {
    /// Pattern to match on source coordinate (e.g., "com.typesafe.play:play")
    pub from_coord_pattern: String,
    /// Version range this guide applies to (below this version)
    pub from_version_below: String,
    /// Target coordinate to migrate to
    pub to_coord: String,
    /// Target version to upgrade to
    pub to_version: String,
    /// List of breaking changes to be aware of
    pub breaking_changes: Vec<String>,
    /// Step-by-step migration instructions
    pub steps: Vec<String>,
    /// Estimated effort in hours (base, before multiplying by code refs)
    pub effort_hours: f32,
    /// Link to official migration documentation
    pub doc_url: String,
    /// Priority: 1 = critical (security), 2 = high (EOL), 3 = recommended, 4 = nice-to-have
    pub priority: u8,
    /// Short summary of why this migration matters
    pub summary: String,
}

/// A prioritized upgrade recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeRecommendation {
    pub coord: String,
    pub current_version: String,
    pub target_version: String,
    pub priority: u8,
    pub priority_label: String,
    pub summary: String,
    pub breaking_changes: Vec<String>,
    pub steps: Vec<String>,
    pub base_effort_hours: f32,
    pub code_references: usize,
    pub estimated_total_hours: f32,
    pub doc_url: String,
}

/// Minimal dep info for advisor
#[derive(Debug, Clone)]
pub struct AdvisorDep {
    pub org: String,
    pub name: String,
    pub version: String,
    pub code_ref_count: usize,
}

impl AdvisorDep {
    pub fn coord(&self) -> String {
        format!("{}:{}", self.org, self.name)
    }
}

/// The embedded migration guide database
const MIGRATION_GUIDES_JSON: &str = r#"[
  {
    "from_coord_pattern": "com.typesafe.play:play",
    "from_version_below": "2.7.0",
    "to_coord": "com.typesafe.play:play",
    "to_version": "2.8.x",
    "breaking_changes": [
      "play.api.mvc.Results.Todo removed",
      "CSRF filter enabled by default",
      "play.api.libs.json.JodaWrites/JodaReads moved to separate module",
      "Removed deprecated Controller trait - use BaseController/AbstractController",
      "Guice is now optional - must add play-guice dependency explicitly",
      "Java CompletionStage used instead of F.Promise"
    ],
    "steps": [
      "Update Play version in build.sbt plugins.sbt to 2.8.x",
      "Add explicit play-guice dependency if using DI",
      "Replace deprecated Controller with AbstractController or BaseController",
      "Replace play.api.mvc.Action with injected ActionBuilder",
      "Update CSRF token handling in forms",
      "Move Joda time JSON support to play-json-joda module",
      "Run 'sbt compile' and fix compilation errors",
      "Test all routes and form submissions for CSRF changes"
    ],
    "effort_hours": 8.0,
    "doc_url": "https://www.playframework.com/documentation/2.8.x/Migration28",
    "priority": 2,
    "summary": "Play 2.6/2.7 is EOL. Upgrade to 2.8.x for security patches and maintained codebase."
  },
  {
    "from_coord_pattern": "com.typesafe.play:play",
    "from_version_below": "3.0.0",
    "to_coord": "org.playframework:play",
    "to_version": "3.0.x",
    "breaking_changes": [
      "Group ID changed from com.typesafe.play to org.playframework",
      "Scala 3 support added, Scala 2.12 dropped",
      "Akka replaced with Apache Pekko",
      "play.api.inject.Module API changes",
      "Java 11 minimum required (Java 17 recommended)",
      "sbt 1.9+ required",
      "EhCache replaced with Caffeine as default cache",
      "play.filters.cors.CORSFilter config changes",
      "Removed play.api.ApplicationLoader.createContext"
    ],
    "steps": [
      "Update sbt to 1.9+",
      "Update Scala to 2.13.x or 3.x",
      "Change all com.typesafe.play group IDs to org.playframework in build.sbt",
      "Replace akka dependencies with pekko equivalents",
      "Update import statements: akka.* -> org.apache.pekko.*",
      "Replace EhCache with Caffeine cache if applicable",
      "Update ApplicationLoader implementations",
      "Review and update CORS configuration",
      "Full regression test suite"
    ],
    "effort_hours": 24.0,
    "doc_url": "https://www.playframework.com/documentation/3.0.x/Migration30",
    "priority": 3,
    "summary": "Play 3.0 moves to Pekko, drops Akka dependency. Major namespace changes required."
  },
  {
    "from_coord_pattern": "com.typesafe.akka:akka-actor",
    "from_version_below": "2.6.0",
    "to_coord": "com.typesafe.akka:akka-actor-typed",
    "to_version": "2.6.x",
    "breaking_changes": [
      "Classic Actor API deprecated in favor of Typed API",
      "ActorSystem creation API changed",
      "Cluster singleton and sharding APIs rewritten",
      "akka.actor.Actor replaced by akka.actor.typed.Behavior",
      "Props replaced by Behaviors.setup/receive",
      "sender() pattern replaced by replyTo in message protocol"
    ],
    "steps": [
      "Update akka version to 2.6.x in build.sbt",
      "Define message protocol traits/case classes for each actor",
      "Convert Actor classes to Behavior using Behaviors.receive or AbstractBehavior",
      "Replace ActorSystem() with ActorSystem(guardianBehavior, name)",
      "Replace actorOf(Props(...)) with context.spawn(behavior, name)",
      "Replace sender() ! response with replyTo ! response",
      "Update Cluster Singleton/Sharding to typed API",
      "Run full test suite - actor behavior tests likely need rewriting"
    ],
    "effort_hours": 16.0,
    "doc_url": "https://doc.akka.io/docs/akka/current/typed/guide/index.html",
    "priority": 2,
    "summary": "Akka Classic is deprecated. Typed actors provide compile-time safety and better maintainability."
  },
  {
    "from_coord_pattern": "com.typesafe.akka:akka",
    "from_version_below": "2.7.0",
    "to_coord": "org.apache.pekko:pekko-actor",
    "to_version": "1.0.x",
    "breaking_changes": [
      "Package namespace changed from akka.* to org.apache.pekko.*",
      "Group ID changed from com.typesafe.akka to org.apache.pekko",
      "Configuration prefix changed from akka.* to pekko.*",
      "Some deprecated APIs removed entirely",
      "License changed from BSL to Apache 2.0"
    ],
    "steps": [
      "Replace all com.typesafe.akka dependencies with org.apache.pekko in build.sbt",
      "Global search-replace: import akka. -> import org.apache.pekko.",
      "Update application.conf: akka { } -> pekko { }",
      "Update reference.conf if you have one",
      "Replace akka-http with pekko-http",
      "Replace akka-stream with pekko-connectors",
      "Compile and fix any remaining references",
      "Update Docker/deployment configs for new artifact names"
    ],
    "effort_hours": 12.0,
    "doc_url": "https://pekko.apache.org/docs/pekko/current/migration/index.html",
    "priority": 2,
    "summary": "Akka 2.7+ uses Business Source License. Pekko is the Apache-licensed fork."
  },
  {
    "from_coord_pattern": "org.codehaus.jackson:jackson",
    "from_version_below": "2.0.0",
    "to_coord": "com.fasterxml.jackson.core:jackson-databind",
    "to_version": "2.17.x",
    "breaking_changes": [
      "Package namespace changed: org.codehaus.jackson -> com.fasterxml.jackson",
      "ObjectMapper API largely compatible but import paths all change",
      "JsonParser/JsonGenerator moved to com.fasterxml.jackson.core",
      "Annotations: @JsonProperty, @JsonIgnore etc. moved to com.fasterxml.jackson.annotation",
      "Custom serializers/deserializers API slightly different"
    ],
    "steps": [
      "Replace org.codehaus.jackson dependencies with com.fasterxml.jackson in build.sbt",
      "Add jackson-databind, jackson-core, jackson-annotations",
      "Global search-replace imports: org.codehaus.jackson -> com.fasterxml.jackson",
      "Update custom serializer/deserializer base classes",
      "For Scala: add jackson-module-scala",
      "Test all JSON serialization/deserialization paths"
    ],
    "effort_hours": 6.0,
    "doc_url": "https://github.com/FasterXML/jackson/wiki/Jackson-Release-2.0",
    "priority": 1,
    "summary": "Jackson 1.x (org.codehaus) is abandoned and has known CVEs. Migrate to FasterXML Jackson 2.x."
  },
  {
    "from_coord_pattern": "commons-collections:commons-collections",
    "from_version_below": "4.0",
    "to_coord": "org.apache.commons:commons-collections4",
    "to_version": "4.4",
    "breaking_changes": [
      "Package changed from org.apache.commons.collections to org.apache.commons.collections4",
      "Generics added to all collection types",
      "Some deprecated classes removed",
      "TransformedMap/LazyMap API changes",
      "Known deserialization gadget in 3.x (CVE-2015-7501)"
    ],
    "steps": [
      "Replace commons-collections:commons-collections with org.apache.commons:commons-collections4 in build.sbt",
      "Update version to 4.4",
      "Search-replace imports: org.apache.commons.collections -> org.apache.commons.collections4",
      "Add type parameters to collection usages",
      "Replace removed/renamed classes with 4.x equivalents",
      "Test thoroughly - behavioral differences in some edge cases"
    ],
    "effort_hours": 4.0,
    "doc_url": "https://commons.apache.org/proper/commons-collections/release_4_0.html",
    "priority": 1,
    "summary": "Commons Collections 3.x has critical deserialization vulnerability (CVE-2015-7501). Upgrade to 4.x."
  },
  {
    "from_coord_pattern": "log4j:log4j",
    "from_version_below": "2.0.0",
    "to_coord": "ch.qos.logback:logback-classic",
    "to_version": "1.4.x",
    "breaking_changes": [
      "Completely different API - Log4j 1.x API replaced with SLF4J",
      "Configuration format changes: log4j.properties -> logback.xml",
      "Appender classes all different",
      "Programmatic configuration API completely different",
      "MDC/NDC API changes"
    ],
    "steps": [
      "Remove log4j:log4j dependency from build.sbt",
      "Add ch.qos.logback:logback-classic and org.slf4j:slf4j-api",
      "Replace import org.apache.log4j.Logger with import org.slf4j.LoggerFactory",
      "Replace Logger.getLogger(class) with LoggerFactory.getLogger(class)",
      "Convert log4j.properties to logback.xml format",
      "Update any programmatic logging configuration",
      "If using Log4j appenders (email, DB, etc.), find Logback equivalents",
      "For bridge: add log4j-over-slf4j to redirect legacy Log4j calls"
    ],
    "effort_hours": 6.0,
    "doc_url": "https://logback.qos.ch/manual/migrationFromLog4j.html",
    "priority": 1,
    "summary": "Log4j 1.x is EOL since 2015 with known vulnerabilities. Migrate to Logback or Log4j 2.x."
  },
  {
    "from_coord_pattern": "org.apache.logging.log4j:log4j-core",
    "from_version_below": "2.17.1",
    "to_coord": "org.apache.logging.log4j:log4j-core",
    "to_version": "2.23.x",
    "breaking_changes": [
      "Log4Shell (CVE-2021-44228) fixed - JNDI lookup disabled by default",
      "Message lookup feature removed",
      "ThreadContext map pattern changes"
    ],
    "steps": [
      "Update log4j-core and log4j-api to 2.23.x in build.sbt",
      "Verify JNDI usage in log patterns - remove any ${jndi:...} patterns",
      "Review custom Appenders for compatibility",
      "If using log4j-core < 2.17.0, this is a CRITICAL security fix"
    ],
    "effort_hours": 1.0,
    "doc_url": "https://logging.apache.org/log4j/2.x/security.html",
    "priority": 1,
    "summary": "CRITICAL: Log4j2 < 2.17.1 is vulnerable to Log4Shell (CVE-2021-44228). Immediate upgrade required."
  },
  {
    "from_coord_pattern": "javax.servlet:servlet-api",
    "from_version_below": "5.0.0",
    "to_coord": "jakarta.servlet:jakarta.servlet-api",
    "to_version": "6.0.0",
    "breaking_changes": [
      "Package namespace changed: javax.servlet -> jakarta.servlet",
      "All javax.* annotations become jakarta.*",
      "javax.inject -> jakarta.inject",
      "javax.persistence -> jakarta.persistence",
      "javax.validation -> jakarta.validation"
    ],
    "steps": [
      "Replace javax.servlet:servlet-api with jakarta.servlet:jakarta.servlet-api in build.sbt",
      "Global search-replace: import javax.servlet -> import jakarta.servlet",
      "Update all javax.inject references to jakarta.inject",
      "If using JPA: javax.persistence -> jakarta.persistence",
      "Update web.xml if applicable",
      "Verify container compatibility (Tomcat 10+, Jetty 11+)",
      "Some frameworks may need specific versions for Jakarta support"
    ],
    "effort_hours": 8.0,
    "doc_url": "https://jakarta.ee/specifications/servlet/6.0/",
    "priority": 3,
    "summary": "javax.* namespace is legacy. Jakarta EE is the maintained successor."
  },
  {
    "from_coord_pattern": "javax.inject:javax.inject",
    "from_version_below": "2.0.0",
    "to_coord": "jakarta.inject:jakarta.inject-api",
    "to_version": "2.0.1",
    "breaking_changes": [
      "Package namespace: javax.inject -> jakarta.inject",
      "@Inject, @Named, @Singleton annotations move to jakarta.inject"
    ],
    "steps": [
      "Replace javax.inject:javax.inject with jakarta.inject:jakarta.inject-api",
      "Search-replace: import javax.inject -> import jakarta.inject",
      "Verify DI framework compatibility with Jakarta Inject"
    ],
    "effort_hours": 2.0,
    "doc_url": "https://jakarta.ee/specifications/dependency-injection/2.0/",
    "priority": 3,
    "summary": "javax.inject is legacy. Migrate to jakarta.inject for forward compatibility."
  },
  {
    "from_coord_pattern": "commons-lang:commons-lang",
    "from_version_below": "3.0",
    "to_coord": "org.apache.commons:commons-lang3",
    "to_version": "3.14.0",
    "breaking_changes": [
      "Package changed: org.apache.commons.lang -> org.apache.commons.lang3",
      "Some method signatures changed for generics",
      "CharEncoding deprecated in favor of StandardCharsets",
      "StringEscapeUtils moved to commons-text"
    ],
    "steps": [
      "Replace commons-lang:commons-lang with org.apache.commons:commons-lang3",
      "Search-replace: import org.apache.commons.lang -> import org.apache.commons.lang3",
      "If using StringEscapeUtils, add org.apache.commons:commons-text dependency",
      "Replace CharEncoding references with java.nio.charset.StandardCharsets"
    ],
    "effort_hours": 3.0,
    "doc_url": "https://commons.apache.org/proper/commons-lang/article3_0.html",
    "priority": 3,
    "summary": "Commons Lang 2.x is unmaintained. Lang3 has improved APIs and generics."
  },
  {
    "from_coord_pattern": "com.google.guava:guava",
    "from_version_below": "30.0",
    "to_coord": "com.google.guava:guava",
    "to_version": "33.x",
    "breaking_changes": [
      "Many @Beta APIs removed or changed",
      "com.google.common.base.Objects replaced by java.util.Objects",
      "com.google.common.base.Optional - consider java.util.Optional",
      "Futures API changes for ListenableFuture",
      "Cache API minor changes"
    ],
    "steps": [
      "Update guava version in build.sbt to 33.x",
      "Replace Guava Optional with java.util.Optional where possible",
      "Replace Guava Objects.equal with java.util.Objects.equals",
      "Check for removed @Beta APIs in your usage",
      "Review Futures usage for API changes",
      "Compile and fix deprecation warnings"
    ],
    "effort_hours": 4.0,
    "doc_url": "https://github.com/google/guava/releases",
    "priority": 3,
    "summary": "Old Guava versions have known CVEs and removed APIs. Update for security and compatibility."
  }
]"#;

/// Load the curated migration guides
pub fn load_migration_guides() -> Vec<MigrationGuide> {
    serde_json::from_str(MIGRATION_GUIDES_JSON).unwrap_or_default()
}

/// Generate upgrade recommendations for a set of dependencies
pub fn generate_upgrade_plan(
    deps: &[AdvisorDep],
    code_ref_counts: &std::collections::HashMap<String, usize>,
) -> Vec<UpgradeRecommendation> {
    let guides = load_migration_guides();
    let mut recommendations: Vec<UpgradeRecommendation> = Vec::new();

    for dep in deps {
        let coord = dep.coord();
        let ref_count = code_ref_counts
            .get(&coord)
            .copied()
            .unwrap_or(dep.code_ref_count);

        for guide in &guides {
            if !matches_coord_pattern(&coord, &guide.from_coord_pattern) {
                continue;
            }

            if !is_version_below(&dep.version, &guide.from_version_below) {
                continue;
            }

            // Calculate effort multiplier based on code references
            let effort_multiplier = if ref_count == 0 {
                1.0
            } else if ref_count < 5 {
                1.0
            } else if ref_count < 20 {
                1.5
            } else if ref_count < 50 {
                2.0
            } else {
                3.0
            };

            let estimated_hours = guide.effort_hours * effort_multiplier;

            let priority_label = match guide.priority {
                1 => "CRITICAL (Security)",
                2 => "HIGH (EOL/Deprecated)",
                3 => "RECOMMENDED",
                _ => "NICE-TO-HAVE",
            }
            .to_string();

            recommendations.push(UpgradeRecommendation {
                coord: coord.clone(),
                current_version: dep.version.clone(),
                target_version: guide.to_version.clone(),
                priority: guide.priority,
                priority_label,
                summary: guide.summary.clone(),
                breaking_changes: guide.breaking_changes.clone(),
                steps: guide.steps.clone(),
                base_effort_hours: guide.effort_hours,
                code_references: ref_count,
                estimated_total_hours: estimated_hours,
                doc_url: guide.doc_url.clone(),
            });
        }
    }

    // Sort by priority (1=highest), then by effort
    recommendations.sort_by(|a, b| {
        a.priority.cmp(&b.priority).then_with(|| {
            b.estimated_total_hours
                .partial_cmp(&a.estimated_total_hours)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    });

    recommendations
}

/// Check if a dependency coordinate matches a pattern
fn matches_coord_pattern(coord: &str, pattern: &str) -> bool {
    // Exact match or prefix match (pattern "com.typesafe.play:play" matches "com.typesafe.play:play_2.13")
    coord == pattern || coord.starts_with(pattern)
}

/// Check if version is below threshold (loose parsing)
fn is_version_below(current: &str, threshold: &str) -> bool {
    let cur = parse_version_loose(current);
    let thr = parse_version_loose(threshold);

    match (cur, thr) {
        (Some((cmaj, cmin, cpatch)), Some((tmaj, tmin, tpatch))) => {
            (cmaj, cmin, cpatch) < (tmaj, tmin, tpatch)
        }
        _ => false, // Can't compare, assume not below
    }
}

/// Loose version parser -> (major, minor, patch)
fn parse_version_loose(v: &str) -> Option<(u32, u32, u32)> {
    let cleaned = v.split('-').next().unwrap_or(v);
    let cleaned = cleaned.split('+').next().unwrap_or(cleaned);
    // Handle "x.y.z" where z might not exist
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

/// Format upgrade plan for terminal output
pub fn format_upgrade_plan(recommendations: &[UpgradeRecommendation]) -> String {
    let mut out = String::new();

    out.push_str(
        "== Upgrade Path Advisor =====================================================\n\n",
    );

    if recommendations.is_empty() {
        out.push_str("  No upgrade recommendations found for current dependencies.\n\n");
        return out;
    }

    let total_hours: f32 = recommendations
        .iter()
        .map(|r| r.estimated_total_hours)
        .sum();
    let critical = recommendations.iter().filter(|r| r.priority == 1).count();
    let high = recommendations.iter().filter(|r| r.priority == 2).count();

    out.push_str(&format!(
        "  {} recommendations  |  {} critical  |  {} high priority  |  ~{:.0} total hours estimated\n\n",
        recommendations.len(), critical, high, total_hours
    ));

    for (i, rec) in recommendations.iter().enumerate() {
        let priority_marker = match rec.priority {
            1 => "[!!!]",
            2 => "[!! ]",
            3 => "[ ! ]",
            _ => "[   ]",
        };

        out.push_str(&format!(
            "  {}. {} {} -> {}\n",
            i + 1,
            priority_marker,
            rec.coord,
            rec.target_version
        ));
        out.push_str(&format!(
            "     Priority: {}  |  Current: {}  |  Effort: ~{:.1}h (base {:.1}h x {} refs)\n",
            rec.priority_label,
            rec.current_version,
            rec.estimated_total_hours,
            rec.base_effort_hours,
            rec.code_references
        ));
        out.push_str(&format!("     {}\n", rec.summary));

        // Breaking changes (show top 3)
        if !rec.breaking_changes.is_empty() {
            out.push_str("     Breaking changes:\n");
            for (j, change) in rec.breaking_changes.iter().take(3).enumerate() {
                out.push_str(&format!("       {}. {}\n", j + 1, change));
            }
            if rec.breaking_changes.len() > 3 {
                out.push_str(&format!(
                    "       ... and {} more\n",
                    rec.breaking_changes.len() - 3
                ));
            }
        }

        // Steps (show top 3)
        if !rec.steps.is_empty() {
            out.push_str("     Migration steps:\n");
            for (j, step) in rec.steps.iter().take(3).enumerate() {
                out.push_str(&format!("       {}. {}\n", j + 1, step));
            }
            if rec.steps.len() > 3 {
                out.push_str(&format!(
                    "       ... and {} more steps\n",
                    rec.steps.len() - 3
                ));
            }
        }

        out.push_str(&format!("     Docs: {}\n", rec.doc_url));
        out.push('\n');
    }

    out
}

/// Format upgrade plan as JSON
pub fn format_upgrade_json(recommendations: &[UpgradeRecommendation]) -> String {
    let total_hours: f32 = recommendations
        .iter()
        .map(|r| r.estimated_total_hours)
        .sum();
    let report = serde_json::json!({
        "upgrade_plan": recommendations,
        "summary": {
            "total_recommendations": recommendations.len(),
            "critical": recommendations.iter().filter(|r| r.priority == 1).count(),
            "high": recommendations.iter().filter(|r| r.priority == 2).count(),
            "recommended": recommendations.iter().filter(|r| r.priority == 3).count(),
            "nice_to_have": recommendations.iter().filter(|r| r.priority >= 4).count(),
            "total_estimated_hours": total_hours,
        }
    });
    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_load_guides() {
        let guides = load_migration_guides();
        assert!(!guides.is_empty());
        // Should have Play, Akka, Jackson, etc.
        assert!(guides.iter().any(|g| g.from_coord_pattern.contains("play")));
        assert!(guides
            .iter()
            .any(|g| g.from_coord_pattern.contains("jackson")));
        assert!(guides
            .iter()
            .any(|g| g.from_coord_pattern.contains("log4j")));
    }

    #[test]
    fn test_version_below() {
        assert!(is_version_below("2.6.0", "2.7.0"));
        assert!(is_version_below("1.9.13", "2.0.0"));
        assert!(!is_version_below("2.8.0", "2.7.0"));
        assert!(!is_version_below("3.0.0", "2.7.0"));
    }

    #[test]
    fn test_coord_matching() {
        assert!(matches_coord_pattern(
            "com.typesafe.play:play_2.13",
            "com.typesafe.play:play"
        ));
        assert!(matches_coord_pattern("log4j:log4j", "log4j:log4j"));
        assert!(!matches_coord_pattern(
            "com.example:other",
            "com.typesafe.play:play"
        ));
    }

    #[test]
    fn test_generate_plan() {
        let deps = vec![
            AdvisorDep {
                org: "com.typesafe.play".to_string(),
                name: "play_2.13".to_string(),
                version: "2.6.25".to_string(),
                code_ref_count: 15,
            },
            AdvisorDep {
                org: "log4j".to_string(),
                name: "log4j".to_string(),
                version: "1.2.17".to_string(),
                code_ref_count: 3,
            },
        ];

        let refs = HashMap::new();
        let plan = generate_upgrade_plan(&deps, &refs);

        // Should find recommendations for both
        assert!(plan.len() >= 2);
        // log4j should be priority 1 (critical/security)
        assert!(plan
            .iter()
            .any(|r| r.coord.contains("log4j") && r.priority == 1));
    }

    #[test]
    fn test_effort_estimation() {
        let deps = vec![AdvisorDep {
            org: "log4j".to_string(),
            name: "log4j".to_string(),
            version: "1.2.17".to_string(),
            code_ref_count: 50,
        }];

        let mut refs = HashMap::new();
        refs.insert("log4j:log4j".to_string(), 50usize);
        let plan = generate_upgrade_plan(&deps, &refs);

        assert!(!plan.is_empty());
        // With 50 refs, multiplier should be 3.0, base 6.0 -> 18.0
        let log4j_rec = plan.iter().find(|r| r.coord.contains("log4j")).unwrap();
        assert!(log4j_rec.estimated_total_hours > log4j_rec.base_effort_hours);
    }
}
