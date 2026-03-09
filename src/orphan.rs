use crate::types::{DepUsageReport, Dependency, TransitiveClassification, UsageVerdict};
use std::collections::{HashMap, HashSet};

/// Well-known transitive dependency chains in the Scala/Play ecosystem.
/// Format: (child_org_prefix, child_name_prefix, parent_org, parent_name_prefix)
/// A lock.sbt entry matching the child is considered linked to the parent.
const KNOWN_CHAINS: &[(&str, &str, &str, &str)] = &[
    // Play framework pulls in these transitives
    ("com.typesafe.play", "", "com.typesafe.play", "play"),
    ("org.playframework", "", "org.playframework", "play"),
    ("com.typesafe.akka", "", "com.typesafe.play", "play"),
    ("com.typesafe.akka", "", "com.typesafe.akka", "akka"),
    ("com.typesafe.akka", "", "com.lightbend.akka", ""),
    // Netty pulled by Akka/Play
    ("io.netty", "", "com.typesafe.akka", ""),
    ("io.netty", "", "com.typesafe.play", "play"),
    // Jackson pulled by play-json, akka-serialization, etc.
    (
        "com.fasterxml.jackson",
        "",
        "com.typesafe.play",
        "play-json",
    ),
    (
        "com.fasterxml.jackson",
        "",
        "com.fasterxml.jackson",
        "jackson",
    ),
    // Guava pulled by many libs
    ("com.google.guava", "", "com.google", ""),
    // SLF4J/Logback chains
    ("org.slf4j", "", "ch.qos.logback", ""),
    ("ch.qos.logback", "", "com.typesafe.play", "play-logback"),
    // Slick pulls in reactive-streams, config, etc.
    ("org.reactivestreams", "", "com.typesafe.slick", ""),
    ("org.reactivestreams", "", "com.typesafe.play", "play-slick"),
    ("com.typesafe.slick", "", "com.typesafe.play", "play-slick"),
    // Kamon pulls its own modules
    ("io.kamon", "", "io.kamon", "kamon"),
    // Spring framework internal chains
    ("org.springframework", "", "org.springframework", "spring"),
    // Twirl (Play template engine)
    ("com.typesafe.play", "twirl", "com.typesafe.play", "play"),
    // Apache commons pulled by many
    ("commons-", "", "org.apache", ""),
    ("org.apache.commons", "", "org.apache", ""),
    // Bouncy Castle pulled by crypto libs
    ("org.bouncycastle", "", "com.pauldijou", ""),
    ("org.bouncycastle", "", "com.nimbusds", ""),
    // Parboiled pulled by spray/akka-http parsing and pegdown (markdown)
    ("org.parboiled", "", "io.spray", ""),
    ("org.parboiled", "", "com.typesafe.akka", "akka-http"),
    ("org.parboiled", "", "org.pegdown", ""),
    ("org.parboiled", "", "com.typesafe.play", "play-doc"),
    // Typesafe config pulled by akka, play, slick
    ("com.typesafe", "config", "com.typesafe.akka", ""),
    ("com.typesafe", "config", "com.typesafe.play", ""),
    ("com.typesafe", "config", "com.typesafe.slick", ""),
    // Scala XML, parser-combinators pulled by many
    ("org.scala-lang.modules", "", "com.typesafe.play", ""),
    ("org.scala-lang.modules", "", "org.scalatest", ""),
    // Cats/cats-effect chains
    ("org.typelevel", "cats", "org.typelevel", "cats"),
    ("org.typelevel", "", "org.http4s", ""),
    // Circe chains
    ("io.circe", "", "io.circe", "circe"),
    // Async HTTP client
    ("org.asynchttpclient", "", "com.typesafe.play", "play-ahc"),
    ("org.asynchttpclient", "", "com.typesafe.play", "play-ws"),
    // Javassist pulled by Guice, Hibernate, etc.
    ("org.javassist", "", "com.google.inject", ""),
    ("org.javassist", "", "net.codingwell", "scala-guice"),
    // CGLIB/ASM pulled by DI frameworks
    ("cglib", "", "com.google.inject", ""),
    ("org.ow2.asm", "", "com.google.inject", ""),
    // Joda-time pulled by play-json, joda-convert
    ("joda-time", "", "com.typesafe.play", "play-json"),
    ("org.joda", "", "joda-time", ""),
    // Xerces/XML — only link if htmlunit is the parent (common case)
    ("xerces", "", "net.sourceforge.htmlunit", ""),
    ("xml-apis", "", "net.sourceforge.htmlunit", ""),
    // HikariCP pulled by Play JDBC
    ("com.zaxxer", "HikariCP", "com.typesafe.play", "play-jdbc"),
    ("com.zaxxer", "HikariCP", "com.typesafe.play", "play"),
    // Specs2 internal chains
    ("org.specs2", "", "org.specs2", "specs2"),
    // Google annotations/utilities pulled by Guice and Guava
    ("com.google.guava", "", "com.google.inject", ""),
    ("com.google.guava", "", "net.codingwell", "scala-guice"),
    ("com.google.code.findbugs", "", "com.google.guava", ""),
    ("com.google.code.findbugs", "", "com.google.inject", ""),
    ("com.google.errorprone", "", "com.google.guava", ""),
    ("com.google.errorprone", "", "com.google.inject", ""),
    ("com.google.j2objc", "", "com.google.guava", ""),
    ("com.google.j2objc", "", "com.google.inject", ""),
    ("org.checkerframework", "", "com.google.guava", ""),
    (
        "org.codehaus.mojo",
        "animal-sniffer",
        "com.google.guava",
        "",
    ),
    // javax pulled by many frameworks
    ("javax.transaction", "", "com.typesafe.play", ""),
    ("javax.transaction", "", "com.typesafe.slick", ""),
    ("javax.servlet", "", "com.typesafe.play", "play"),
    ("javax.activation", "", "com.typesafe.play", ""),
    ("javax.xml.bind", "", "com.typesafe.play", ""),
    // AOP alliance pulled by Guice
    ("aopalliance", "", "com.google.inject", ""),
    ("aopalliance", "", "net.codingwell", "scala-guice"),
    // Reactive streams pulled by Akka
    ("org.reactivestreams", "", "com.typesafe.akka", ""),
    // BoneCP / connection pools
    ("com.jolbox", "", "com.typesafe.play", "play-jdbc"),
    // DOM4J pulled by many XML libs
    ("dom4j", "", "com.typesafe.play", ""),
    // Hamcrest pulled by test frameworks
    ("org.hamcrest", "", "org.specs2", ""),
    ("org.hamcrest", "", "org.scalatest", ""),
    ("org.hamcrest", "", "junit", ""),
    // Objenesis pulled by Mockito
    ("org.objenesis", "", "org.mockito", ""),
    // Scala-STM pulled by Akka
    ("org.scala-stm", "", "com.typesafe.akka", ""),
    // HDR Histogram pulled by Kamon
    ("org.hdrhistogram", "", "io.kamon", ""),
    // JLine — rarely needed as transitive, usually orphaned. Only link to sbt itself.
    ("jline", "", "org.scala-sbt", ""),
    // Logback extensions
    ("org.logback-extensions", "", "ch.qos.logback", ""),
    // Reflections pulled by Play testing
    ("org.reflections", "", "com.typesafe.play", "play-test"),
    // Webbit pulled by Play testing (Selenium)
    ("org.webbitserver", "", "com.typesafe.play", "play-test"),
    // Tyrex transaction manager pulled by Play
    ("tyrex", "", "com.typesafe.play", "play-jdbc"),
    // Neko HTML / HTML parsers pulled by Selenium/test
    (
        "net.sourceforge.nekohtml",
        "",
        "org.seleniumhq.selenium",
        "",
    ),
    (
        "net.sourceforge.nekohtml",
        "",
        "com.typesafe.play",
        "play-test",
    ),
    // Amazon Ion pulled by AWS SDK
    ("software.amazon.ion", "", "com.amazonaws", ""),
    // Netty reactive streams
    ("com.typesafe.netty", "", "com.typesafe.play", "play"),
    ("com.typesafe.netty", "", "com.typesafe.akka", ""),
    // Paranamer pulled by Jackson
    (
        "com.thoughtworks.paranamer",
        "",
        "com.fasterxml.jackson",
        "",
    ),
    // FluentLenium pulled by Play test
    ("org.fluentlenium", "", "com.typesafe.play", "play-test"),
    // Fest-assert pulled by FluentLenium/test
    ("org.easytesting", "", "com.typesafe.play", "play-test"),
    ("org.easytesting", "", "org.fluentlenium", ""),
    // OAuth signpost pulled by Play WS
    ("oauth.signpost", "", "com.typesafe.play", "play-ws"),
    // AspectJ pulled by Kamon
    ("org.aspectj", "", "io.kamon", ""),
    // CSS/SAC parsers pulled by HTML testing
    (
        "net.sourceforge.cssparser",
        "",
        "org.seleniumhq.selenium",
        "",
    ),
    ("org.w3c.css", "", "net.sourceforge.cssparser", ""),
    ("org.w3c.css", "", "com.typesafe.play", "play-test"),
    // HTMLUnit pulled by Selenium
    (
        "net.sourceforge.htmlunit",
        "",
        "org.seleniumhq.selenium",
        "",
    ),
    (
        "net.sourceforge.htmlcleaner",
        "",
        "net.sourceforge.htmlunit",
        "",
    ),
    // Commons pulled by many JVM libs
    ("commons-logging", "", "com.amazonaws", ""),
    ("commons-logging", "", "org.apache.httpcomponents", ""),
    ("commons-codec", "", "org.apache.httpcomponents", ""),
    ("commons-codec", "", "com.amazonaws", ""),
    ("commons-io", "", "com.typesafe.play", ""),
    ("commons-beanutils", "", "commons-validator", ""),
    ("commons-digester", "", "commons-beanutils", ""),
    ("commons-collections", "", "commons-beanutils", ""),
    ("commons-validator", "", "com.typesafe.play", ""),
    // HTTP components pulled by AWS SDK
    ("org.apache.httpcomponents", "", "com.amazonaws", ""),
    // Selenium pulled by Play test
    (
        "org.seleniumhq.selenium",
        "",
        "com.typesafe.play",
        "play-test",
    ),
    // Xalan pulled by XML processing chains
    ("xalan", "", "xerces", ""),
    ("xalan", "", "net.sourceforge.htmlunit", ""),
    ("xalan", "serializer", "xalan", "xalan"),
    // Xerces/XML pulled broadly (not just htmlunit)
    ("xerces", "", "xalan", ""),
    ("xml-apis", "", "xerces", ""),
    ("xml-apis", "", "xalan", ""),
    // JNA pulled by Selenium and Kamon
    ("net.java.dev.jna", "", "io.kamon", "sigar"),
    ("net.java.dev.jna", "", "org.seleniumhq.selenium", ""),
    // Google protobuf pulled by many libs
    ("com.google.protobuf", "", "com.google", ""),
    // Apache Ant pulled by AspectJ
    ("org.apache.ant", "", "org.aspectj", ""),
    // JDOM pulled by various XML libs
    ("org.jdom", "", "com.typesafe.play", ""),
    // Scalacheck pulled by Specs2/Scalatest
    ("org.scalacheck", "", "org.specs2", ""),
    ("org.scalacheck", "", "org.scalatest", ""),
    // Atteo classindex
    ("org.atteo.classindex", "", "io.kamon", ""),
    // Scalaz pulled by Specs2
    ("org.scalaz", "", "org.specs2", ""),
    // Amazon commons compress
    (
        "org.apache.commons",
        "commons-compress",
        "com.amazonaws",
        "",
    ),
    (
        "org.apache.commons",
        "commons-exec",
        "org.seleniumhq.selenium",
        "",
    ),
    ("org.apache.commons", "commons-lang3", "com.amazonaws", ""),
    // Pegdown pulled by Play documentation
    ("org.pegdown", "", "com.typesafe.play", "play-doc"),
    ("org.pegdown", "", "com.typesafe.play", "play"),
    // Ehcache pulled by Play cache
    ("net.sf.ehcache", "", "com.typesafe.play", "play-cache"),
    ("net.sf.ehcache", "", "com.typesafe.play", "play"),
    // Jetty pulled by Selenium and websocket libs
    ("org.eclipse.jetty", "", "org.seleniumhq.selenium", ""),
    ("org.eclipse.jetty", "", "org.eclipse.jetty", "jetty"),
    // Ning async-http-client pulled by Play WS (older Play versions)
    (
        "com.ning",
        "async-http-client",
        "com.typesafe.play",
        "play-ws",
    ),
    ("com.ning", "async-http-client", "com.typesafe.play", "play"),
    // Parboiled internal: parboiled-core pulled by parboiled-java
    (
        "org.parboiled",
        "parboiled-core",
        "org.parboiled",
        "parboiled",
    ),
    // Cloudinary internal chain
    ("com.cloudinary", "", "com.cloudinary", "cloudinary"),
    // Edulify pulled by Play
    ("com.edulify", "", "com.typesafe.play", "play"),
    // JQuery pulled by Play test/WebJars
    ("org.webjars", "", "com.typesafe.play", "play"),
    // SSL config pulled by Akka
    ("com.typesafe", "ssl-config", "com.typesafe.akka", ""),
    ("com.typesafe", "ssl-config", "com.typesafe.play", ""),
    // Async HTTP client backend for sttp
    ("com.softwaremill.sttp", "", "com.softwaremill.sttp", ""),
    ("com.softwaremill.sttp", "", "com.softwaremill", ""),
    // Odelay/retry pulled by circuit breakers etc.
    ("com.softwaremill.odelay", "", "com.softwaremill", ""),
    ("com.softwaremill.retry", "", "com.softwaremill", ""),
    // Hootsuite circuit breaker
    ("com.hootsuite", "", "com.hootsuite", ""),
    // JDBCDSLOG pulled by Play JDBC/Edulify
    ("com.googlecode.usc", "", "com.edulify", ""),
    ("com.googlecode.usc", "", "com.typesafe.play", "play-jdbc"),
    // Kamon system-metrics → sigar-loader
    ("io.kamon", "sigar-loader", "io.kamon", "kamon-system"),
    // Geohash pulled by location libs
    ("ch.hsr", "", "com.atomtickets", ""),
    // Libphonenumber pulled by many services
    ("com.googlecode.libphonenumber", "", "com.typesafe.play", ""),
    ("com.googlecode.libphonenumber", "", "com.google", ""),
    // ESR geometry pulled by location libs
    ("com.esri.geometry", "", "com.atomtickets", ""),
    // JSuereth scala-arm pulled by various libs
    ("com.jsuereth", "", "com.typesafe", ""),
    // Kxbmap configs pulled by metrics/config libs
    ("com.github.kxbmap", "", "io.kamon", ""),
    ("com.github.kxbmap", "", "com.typesafe", ""),
    // Play extensions / cvogt
    ("org.cvogt", "", "com.typesafe.play", ""),
    // Scala-logging pulled by many
    ("com.typesafe.scala-logging", "", "com.typesafe", ""),
    ("com.typesafe.scala-logging", "", "com.typesafe.play", ""),
];

/// Classify all transitive deps (from lock.sbt) against active direct deps.
///
/// Uses four heuristics in priority order:
/// 1. Code-referenced: dep has Active or DeadImport verdict from usage analysis
/// 2. Known transitive chains: hardcoded parent→child mappings for the Scala ecosystem
/// 3. Exact org matching: lock.sbt dep shares exact org with an active direct dep
/// 4. Version cluster detection: 3+ lock.sbt deps with same org + exact version = cluster
///
/// Anything not matched by any heuristic is classified as LikelyOrphaned.
pub fn classify_transitive_deps(
    direct_deps: &[Dependency],
    transitive_deps: &[Dependency],
    usage_reports: &[DepUsageReport],
) -> HashMap<String, TransitiveClassification> {
    let mut classifications: HashMap<String, TransitiveClassification> = HashMap::new();

    // Build lookup: coord → usage verdict
    let usage_map: HashMap<String, &DepUsageReport> =
        usage_reports.iter().map(|r| (r.coord.clone(), r)).collect();

    // Build set of active direct dep coords and orgs
    let active_direct_coords: HashSet<String> = direct_deps
        .iter()
        .filter(|d| {
            let coord = d.coord();
            usage_map
                .get(&coord)
                .map(|r| {
                    r.verdict == UsageVerdict::Active || r.verdict == UsageVerdict::RuntimeOnly
                })
                .unwrap_or(true) // if not analyzed, assume active
        })
        .map(|d| d.coord())
        .collect();

    let active_direct_orgs: HashSet<&str> = direct_deps
        .iter()
        .filter(|d| active_direct_coords.contains(&d.coord()))
        .map(|d| d.org.as_str())
        .collect();

    // Pre-compute org-prefix segments for matching (min 2 segments: e.g. "com.typesafe")
    let active_org_prefixes: Vec<String> = active_direct_orgs
        .iter()
        .map(|org| {
            let parts: Vec<&str> = org.split('.').collect();
            if parts.len() >= 2 {
                format!("{}.{}", parts[0], parts[1])
            } else {
                org.to_string()
            }
        })
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    // Build version clusters: org_prefix → version → count
    let mut version_clusters: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();
    for dep in transitive_deps {
        let org_prefix = org_prefix_2(&dep.org);
        version_clusters
            .entry(org_prefix)
            .or_default()
            .entry(dep.version.clone())
            .or_default()
            .push(dep.coord());
    }

    // Build combined parent pool: direct + transitive deps that are active/runtime
    // This handles Play SBT plugin injected deps (e.g. com.typesafe.play:play is transitive
    // but still serves as a parent for chain matching)
    let all_parent_deps: Vec<Dependency> = direct_deps
        .iter()
        .chain(transitive_deps.iter())
        .cloned()
        .collect();
    let active_any_coords: HashSet<String> = all_parent_deps
        .iter()
        .filter(|d| {
            let c = d.coord();
            if active_direct_coords.contains(&c) {
                return true;
            }
            usage_map
                .get(&c)
                .map(|r| {
                    r.verdict == UsageVerdict::Active
                        || r.verdict == UsageVerdict::RuntimeOnly
                        || r.verdict == UsageVerdict::DeadImport
                })
                .unwrap_or(false)
        })
        .map(|d| d.coord())
        .collect();

    // Now classify each transitive dep
    for dep in transitive_deps {
        let coord = dep.coord();

        // 1. Check if code-referenced
        if let Some(report) = usage_map.get(&coord) {
            if report.verdict == UsageVerdict::Active {
                classifications.insert(coord, TransitiveClassification::CodeReferenced);
                continue;
            }
            if report.verdict == UsageVerdict::RuntimeOnly {
                classifications.insert(coord, TransitiveClassification::RuntimeTransitive);
                continue;
            }
        }

        // 2. Check known transitive chains (against both direct AND active transitive deps)
        if let Some(parent) = find_known_chain_parent(dep, &all_parent_deps, &active_any_coords) {
            classifications.insert(
                coord,
                TransitiveClassification::LinkedTo {
                    parent_coord: parent.0,
                    reason: parent.1,
                },
            );
            continue;
        }

        // 3. Org matching — exact org match with an active direct dep
        if active_direct_orgs.contains(dep.org.as_str()) {
            let matching_org = dep.org.clone();
            classifications.insert(
                coord,
                TransitiveClassification::LinkedTo {
                    parent_coord: matching_org.clone(),
                    reason: format!("Exact org match: {}", matching_org),
                },
            );
            continue;
        }

        // 3b. Internal/private dep linking — deps with non-standard orgs
        //     (no dots in org name). Link only if the dep name contains the org
        //     of an active dep (e.g. "catalogservicemodel" contains "catalogservice"
        //     and "catalogserviceclient" is active).
        if is_internal_org(&dep.org) {
            let linked_by = active_any_coords.iter().find(|c| {
                if let Some(idx) = c.find(':') {
                    let active_org = &c[..idx];
                    // Check if dep org is a substring of active org or vice versa
                    // (e.g. "catalogservicemodel" and "catalogserviceclient" share "catalogservice")
                    if is_internal_org(active_org) {
                        // Extract common prefix (at least 8 chars to avoid false matches)
                        let shorter = std::cmp::min(dep.org.len(), active_org.len());
                        if shorter >= 8 {
                            let prefix_len = dep
                                .org
                                .chars()
                                .zip(active_org.chars())
                                .take_while(|(a, b)| a == b)
                                .count();
                            prefix_len >= 8
                        } else {
                            dep.org == active_org
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            });
            if let Some(parent) = linked_by {
                classifications.insert(
                    coord,
                    TransitiveClassification::LinkedTo {
                        parent_coord: parent.clone(),
                        reason: format!("Internal dep: name similarity with {}", parent),
                    },
                );
                continue;
            }
        }

        // 4. Broad org-prefix match: if 2-segment org prefix matches ANY active dep
        //    (including active transitive deps). More aggressive than exact org match
        //    but catches deps pulled by internal libs sharing an org prefix.
        let dep_prefix = org_prefix_2(&dep.org);
        let has_active_prefix = active_any_coords.iter().any(|c| {
            if let Some(idx) = c.find(':') {
                org_prefix_2(&c[..idx]) == dep_prefix
            } else {
                false
            }
        });
        if has_active_prefix {
            classifications.insert(
                coord,
                TransitiveClassification::LinkedTo {
                    parent_coord: dep_prefix.clone(),
                    reason: format!("Org prefix match: {}", dep_prefix),
                },
            );
            continue;
        }

        // 5. Version cluster: if this dep is part of a cluster of 3+ deps
        //    with the same org prefix + version, AND at least one member is already
        //    classified as linked/active, the whole cluster is linked
        let dep_org_prefix = org_prefix_2(&dep.org);
        if let Some(versions) = version_clusters.get(&dep_org_prefix) {
            if let Some(cluster_members) = versions.get(&dep.version) {
                if cluster_members.len() >= 3 {
                    // Check if any cluster member is already linked or active
                    let has_linked_member = cluster_members.iter().any(|c| {
                        classifications
                            .get(c)
                            .map(|cl| !cl.is_orphaned())
                            .unwrap_or(false)
                            || active_any_coords.contains(c)
                    });

                    if has_linked_member {
                        classifications.insert(
                            coord,
                            TransitiveClassification::LinkedTo {
                                parent_coord: dep_org_prefix.clone(),
                                reason: format!(
                                    "Version cluster: {} deps at v{} in {}",
                                    cluster_members.len(),
                                    dep.version,
                                    dep_org_prefix
                                ),
                            },
                        );
                        continue;
                    }
                }
            }
        }

        // No match — likely orphaned
        classifications.insert(coord, TransitiveClassification::LikelyOrphaned);
    }

    // Pass 2: Transitive propagation — if a dep classified as orphaned has a chain rule
    // pointing to a TRANSITIVE dep that is itself linked, propagate the link.
    // This handles multi-hop chains through lock.sbt deps.
    let mut changed = true;
    let max_iterations = 5;
    let mut iteration = 0;
    while changed && iteration < max_iterations {
        changed = false;
        iteration += 1;
        let current_linked: HashSet<String> = classifications
            .iter()
            .filter(|(_, c)| !c.is_orphaned())
            .map(|(k, _)| k.clone())
            .collect();

        for dep in transitive_deps {
            let coord = dep.coord();
            if let Some(c) = classifications.get(&coord) {
                if !c.is_orphaned() {
                    continue; // already linked
                }
            }

            // Try chain matching against currently-linked transitive deps
            if let Some(parent) = find_known_chain_parent(dep, &all_parent_deps, &current_linked) {
                classifications.insert(
                    coord,
                    TransitiveClassification::LinkedTo {
                        parent_coord: parent.0,
                        reason: format!("{} (propagated)", parent.1),
                    },
                );
                changed = true;
                continue;
            }
        }
    }

    classifications
}

/// Check if an org looks like an internal/private dependency.
/// Internal deps typically have no dots in the org name (e.g. "donkeytron", "catalogutils")
/// or use a company-specific prefix.
fn is_internal_org(org: &str) -> bool {
    // No dots = almost certainly internal (e.g. "donkeytron", "accountserviceclient")
    if !org.contains('.') {
        return true;
    }
    false
}

/// Extract 2-segment org prefix: "com.typesafe.play" → "com.typesafe"
fn org_prefix_2(org: &str) -> String {
    let parts: Vec<&str> = org.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[0], parts[1])
    } else {
        org.to_string()
    }
}

/// Check if a transitive dep matches any known chain rule and return the parent coord + reason
fn find_known_chain_parent(
    dep: &Dependency,
    direct_deps: &[Dependency],
    active_coords: &HashSet<String>,
) -> Option<(String, String)> {
    for &(child_org, child_name, parent_org, parent_name) in KNOWN_CHAINS {
        // Check if this dep matches the child pattern
        let org_match = if child_org.is_empty() {
            true
        } else {
            dep.org.starts_with(child_org)
        };
        let name_match = if child_name.is_empty() {
            true
        } else {
            dep.name.starts_with(child_name)
        };

        if !org_match || !name_match {
            continue;
        }

        // Find the parent in direct deps
        for parent_dep in direct_deps {
            if !active_coords.contains(&parent_dep.coord()) {
                continue;
            }
            let p_org_match = if parent_org.is_empty() {
                true
            } else {
                parent_dep.org.starts_with(parent_org)
            };
            let p_name_match = if parent_name.is_empty() {
                true
            } else {
                parent_dep.name.starts_with(parent_name)
            };

            if p_org_match && p_name_match {
                return Some((
                    parent_dep.coord(),
                    format!("Known chain: {} → {}", dep.coord(), parent_dep.coord()),
                ));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DepUsageReport, Dependency, UsageVerdict};

    fn make_dep(org: &str, name: &str, version: &str, transitive: bool) -> Dependency {
        Dependency {
            org: org.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            scope: None,
            cross_compiled: false,
            source_file: if transitive {
                "lock.sbt".to_string()
            } else {
                "build.sbt".to_string()
            },
            is_transitive: transitive,
        }
    }

    fn make_report(
        coord: &str,
        version: &str,
        verdict: UsageVerdict,
        is_direct: bool,
    ) -> DepUsageReport {
        DepUsageReport {
            coord: coord.to_string(),
            version: version.to_string(),
            is_direct,
            verdict,
            import_files: vec![],
            usage_files: vec![],
            symbols_found: vec![],
            usage_count: 0,
            source_file: String::new(),
        }
    }

    #[test]
    fn test_code_referenced_dep() {
        let direct = vec![make_dep("com.typesafe.play", "play-slick", "3.0.1", false)];
        let transitive = vec![make_dep("com.typesafe.slick", "slick", "3.2.0", true)];
        let reports = vec![
            make_report(
                "com.typesafe.play:play-slick",
                "3.0.1",
                UsageVerdict::Active,
                true,
            ),
            make_report(
                "com.typesafe.slick:slick",
                "3.2.0",
                UsageVerdict::Active,
                false,
            ),
        ];

        let result = classify_transitive_deps(&direct, &transitive, &reports);
        assert_eq!(
            result.get("com.typesafe.slick:slick"),
            Some(&TransitiveClassification::CodeReferenced)
        );
    }

    #[test]
    fn test_known_chain_link() {
        let direct = vec![make_dep("com.typesafe.play", "play-json", "2.6.10", false)];
        let transitive = vec![make_dep(
            "com.fasterxml.jackson.core",
            "jackson-databind",
            "2.9.9",
            true,
        )];
        let reports = vec![
            make_report(
                "com.typesafe.play:play-json",
                "2.6.10",
                UsageVerdict::Active,
                true,
            ),
            make_report(
                "com.fasterxml.jackson.core:jackson-databind",
                "2.9.9",
                UsageVerdict::Unused,
                false,
            ),
        ];

        let result = classify_transitive_deps(&direct, &transitive, &reports);
        let class = result
            .get("com.fasterxml.jackson.core:jackson-databind")
            .unwrap();
        match class {
            TransitiveClassification::LinkedTo { parent_coord, .. } => {
                assert_eq!(parent_coord, "com.typesafe.play:play-json");
            }
            _ => panic!("Expected LinkedTo, got {:?}", class),
        }
    }

    #[test]
    fn test_org_prefix_match() {
        let direct = vec![make_dep("io.kamon", "kamon-core", "1.1.3", false)];
        let transitive = vec![make_dep("io.kamon", "kamon-scala-future", "1.0.0", true)];
        let reports = vec![
            make_report("io.kamon:kamon-core", "1.1.3", UsageVerdict::Active, true),
            make_report(
                "io.kamon:kamon-scala-future",
                "1.0.0",
                UsageVerdict::Unused,
                false,
            ),
        ];

        let result = classify_transitive_deps(&direct, &transitive, &reports);
        let class = result.get("io.kamon:kamon-scala-future").unwrap();
        match class {
            TransitiveClassification::LinkedTo { reason, .. } => {
                assert!(
                    reason.contains("Org prefix") || reason.contains("Known chain"),
                    "Expected org prefix or chain match, got: {}",
                    reason
                );
            }
            _ => panic!("Expected LinkedTo, got {:?}", class),
        }
    }

    #[test]
    fn test_likely_orphaned() {
        let direct = vec![make_dep("com.typesafe.play", "play-slick", "3.0.1", false)];
        let transitive = vec![make_dep("org.parboiled", "parboiled-core", "1.1.7", true)];
        let reports = vec![
            make_report(
                "com.typesafe.play:play-slick",
                "3.0.1",
                UsageVerdict::Active,
                true,
            ),
            make_report(
                "org.parboiled:parboiled-core",
                "1.1.7",
                UsageVerdict::Unused,
                false,
            ),
        ];

        let result = classify_transitive_deps(&direct, &transitive, &reports);
        // parboiled should be linked via known chain to akka-http or spray
        // If no spray/akka-http in direct deps, it should be orphaned
        let class = result.get("org.parboiled:parboiled-core").unwrap();
        assert!(
            class.is_orphaned(),
            "Expected LikelyOrphaned, got {:?}",
            class
        );
    }

    #[test]
    fn test_version_cluster() {
        let direct = vec![make_dep("com.typesafe.play", "play", "2.6.20", false)];
        let transitive = vec![
            make_dep("io.netty", "netty-handler", "4.0.56.Final", true),
            make_dep("io.netty", "netty-codec", "4.0.56.Final", true),
            make_dep("io.netty", "netty-transport", "4.0.56.Final", true),
            make_dep("io.netty", "netty-buffer", "4.0.56.Final", true),
        ];
        let reports = vec![
            make_report(
                "com.typesafe.play:play",
                "2.6.20",
                UsageVerdict::Active,
                true,
            ),
            make_report(
                "io.netty:netty-handler",
                "4.0.56.Final",
                UsageVerdict::Unused,
                false,
            ),
            make_report(
                "io.netty:netty-codec",
                "4.0.56.Final",
                UsageVerdict::Unused,
                false,
            ),
            make_report(
                "io.netty:netty-transport",
                "4.0.56.Final",
                UsageVerdict::Unused,
                false,
            ),
            make_report(
                "io.netty:netty-buffer",
                "4.0.56.Final",
                UsageVerdict::Unused,
                false,
            ),
        ];

        let result = classify_transitive_deps(&direct, &transitive, &reports);
        // All netty deps should be linked (via known chain to play or version cluster)
        for dep in &transitive {
            let class = result.get(&dep.coord()).unwrap();
            assert!(
                !class.is_orphaned(),
                "{} should not be orphaned, got {:?}",
                dep.coord(),
                class
            );
        }
    }

    #[test]
    fn test_runtime_transitive() {
        let direct = vec![make_dep("com.typesafe.play", "play", "2.6.20", false)];
        let transitive = vec![make_dep("ch.qos.logback", "logback-classic", "1.2.3", true)];
        let reports = vec![
            make_report(
                "com.typesafe.play:play",
                "2.6.20",
                UsageVerdict::Active,
                true,
            ),
            make_report(
                "ch.qos.logback:logback-classic",
                "1.2.3",
                UsageVerdict::RuntimeOnly,
                false,
            ),
        ];

        let result = classify_transitive_deps(&direct, &transitive, &reports);
        assert_eq!(
            result.get("ch.qos.logback:logback-classic"),
            Some(&TransitiveClassification::RuntimeTransitive)
        );
    }

    #[test]
    fn test_empty_inputs() {
        let result = classify_transitive_deps(&[], &[], &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_org_prefix_extraction() {
        assert_eq!(org_prefix_2("com.typesafe.play"), "com.typesafe");
        assert_eq!(org_prefix_2("io.netty"), "io.netty");
        assert_eq!(org_prefix_2("mysql"), "mysql");
        assert_eq!(org_prefix_2("org.scala-lang.modules"), "org.scala-lang");
    }
}
