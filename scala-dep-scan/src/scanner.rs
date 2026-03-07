use crate::types::{CodeReference, DepUsageReport, Dependency, UsageVerdict};
use anyhow::Result;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

/// Known runtime-only artifact patterns — these are injected/wired at runtime,
/// not via import statements. Flagging them as "unused" would be a false positive.
const RUNTIME_PATTERNS: &[(&str, &str)] = &[
    ("com.google.inject", ""), // Guice DI
    ("com.typesafe.play", "play-guice"),
    ("com.typesafe.play", "filters-helpers"),
    ("com.typesafe.play", "play-logback"),
    ("com.typesafe.play", "play-jdbc-evolutions"),
    ("ch.qos.logback", ""), // logging backend
    ("org.slf4j", "slf4j-api"),
    ("net.logstash.logback", ""),
    ("com.typesafe", "config"), // loaded via ConfigFactory at runtime
    ("org.scala-lang", ""),     // stdlib
    ("org.scala-lang.modules", ""),
    ("com.typesafe.scala-logging", ""),
    ("com.novocode", ""), // test runners
    ("org.scalatest", ""),
    ("org.specs2", ""),
    ("junit", ""),
    ("org.mockito", ""),
    ("org.scalatestplus", ""),
    ("com.typesafe.play", "play-test"),
    ("org.scalameta", ""), // compiler plugins
    ("org.wartremover", ""),
    ("com.github.ghik", ""),
];

/// Expanded mapping of Maven coordinates to Java/Scala package prefixes AND
/// common class/symbol names from that library.
struct DepProfile {
    /// Java package prefixes this dep lives under
    packages: Vec<&'static str>,
    /// Well-known class/trait/object names from this dep
    symbols: Vec<&'static str>,
}

fn dep_profile(org: &str, name: &str) -> DepProfile {
    let profiles: &[(&str, &str, &[&str], &[&str])] = &[
        // (org_contains, name_contains, packages, symbols)
        (
            "com.typesafe.play",
            "play-json",
            &["play.api.libs.json"],
            &[
                "Json", "JsValue", "JsObject", "JsArray", "JsString", "Reads", "Writes", "Format",
                "JsPath", "JsResult",
            ],
        ),
        (
            "com.typesafe.play",
            "",
            &["play", "play.api", "play.api.mvc", "play.api.http"],
            &[
                "Action",
                "Controller",
                "Request",
                "Result",
                "Ok",
                "BadRequest",
                "NotFound",
                "Redirect",
                "BaseController",
                "AbstractController",
                "MessagesAbstractController",
                "AnyContent",
                "BodyParsers",
            ],
        ),
        (
            "com.typesafe.akka",
            "akka-http",
            &["akka.http"],
            &[
                "HttpRequest",
                "HttpResponse",
                "Route",
                "Directives",
                "Http",
                "ServerBinding",
            ],
        ),
        (
            "com.typesafe.akka",
            "akka-stream",
            &["akka.stream"],
            &[
                "Source",
                "Sink",
                "Flow",
                "Materializer",
                "ActorMaterializer",
                "RunnableGraph",
            ],
        ),
        (
            "com.typesafe.akka",
            "akka-actor",
            &["akka.actor", "akka"],
            &[
                "ActorSystem",
                "ActorRef",
                "Actor",
                "Props",
                "PoisonPill",
                "ActorContext",
                "Scheduler",
                "Terminated",
                "Inbox",
            ],
        ),
        (
            "com.amazonaws",
            "",
            &["com.amazonaws", "software.amazon.awssdk"],
            &[
                "AmazonS3",
                "AmazonSQS",
                "AmazonDynamoDB",
                "AWSCredentials",
                "S3Client",
                "SqsClient",
                "DynamoDbClient",
                "AmazonSNS",
                "AmazonEC2",
                "PutObjectRequest",
                "GetObjectRequest",
                "S3Object",
                "Message",
                "SendMessageRequest",
                "Region",
            ],
        ),
        (
            "software.amazon.awssdk",
            "",
            &["software.amazon.awssdk"],
            &[
                "S3Client",
                "SqsClient",
                "DynamoDbClient",
                "Region",
                "AwsCredentials",
                "StaticCredentialsProvider",
                "DefaultCredentialsProvider",
            ],
        ),
        (
            "org.springframework",
            "spring-core",
            &["org.springframework"],
            &[
                "ApplicationContext",
                "BeanFactory",
                "Resource",
                "Environment",
                "ClassPathResource",
                "PathMatchingResourcePatternResolver",
            ],
        ),
        (
            "org.springframework",
            "spring-web",
            &["org.springframework.web", "org.springframework.http"],
            &[
                "RestTemplate",
                "HttpEntity",
                "ResponseEntity",
                "HttpHeaders",
                "MediaType",
                "HttpMethod",
                "RequestEntity",
                "WebClient",
            ],
        ),
        (
            "org.springframework",
            "spring-context",
            &["org.springframework.context", "org.springframework.beans"],
            &[
                "ApplicationContext",
                "AnnotationConfigApplicationContext",
                "Bean",
                "Component",
                "Service",
                "Repository",
                "Autowired",
                "Configuration",
            ],
        ),
        (
            "com.fasterxml.jackson",
            "",
            &["com.fasterxml.jackson"],
            &[
                "ObjectMapper",
                "JsonNode",
                "ObjectNode",
                "ArrayNode",
                "JsonParser",
                "JsonGenerator",
                "TypeReference",
                "JsonProperty",
                "JsonIgnore",
                "JsonCreator",
                "DeserializationFeature",
                "SerializationFeature",
            ],
        ),
        (
            "io.netty",
            "",
            &["io.netty"],
            &[
                "Bootstrap",
                "ServerBootstrap",
                "Channel",
                "ChannelFuture",
                "EventLoopGroup",
                "NioEventLoopGroup",
                "ChannelPipeline",
                "ChannelHandler",
                "ByteBuf",
                "ChannelHandlerContext",
                "NioSocketChannel",
            ],
        ),
        (
            "org.apache.commons",
            "commons-collections",
            &["org.apache.commons.collections"],
            &[
                "CollectionUtils",
                "MapUtils",
                "ListUtils",
                "SetUtils",
                "BagUtils",
                "TransformedMap",
                "LazyMap",
                "MultiValueMap",
            ],
        ),
        (
            "org.apache.commons",
            "commons-lang",
            &["org.apache.commons.lang"],
            &[
                "StringUtils",
                "ArrayUtils",
                "RandomStringUtils",
                "NumberUtils",
                "BooleanUtils",
                "ObjectUtils",
                "ClassUtils",
                "SystemUtils",
            ],
        ),
        (
            "org.apache.commons",
            "commons-io",
            &["org.apache.commons.io"],
            &[
                "FileUtils",
                "IOUtils",
                "FilenameUtils",
                "FileSystemUtils",
                "DirectoryWalker",
                "LineIterator",
            ],
        ),
        (
            "org.apache.logging.log4j",
            "",
            &["org.apache.logging.log4j"],
            &[
                "LogManager",
                "Logger",
                "Level",
                "Appender",
                "Layout",
                "LoggingEvent",
                "PatternLayout",
                "LoggerContext",
            ],
        ),
        (
            "com.google.guava",
            "",
            &["com.google.common"],
            &[
                "ImmutableList",
                "ImmutableMap",
                "ImmutableSet",
                "Lists",
                "Maps",
                "Sets",
                "Optional",
                "Preconditions",
                "Strings",
                "Objects",
                "Futures",
                "ListenableFuture",
                "Multimap",
                "HashMultimap",
                "ArrayListMultimap",
                "CacheBuilder",
                "LoadingCache",
            ],
        ),
        (
            "org.postgresql",
            "",
            &["org.postgresql"],
            &["Driver", "PGConnection", "PGStatement", "PGResultSet"],
        ),
        (
            "com.zaxxer",
            "hikari",
            &["com.zaxxer.hikari"],
            &["HikariDataSource", "HikariConfig", "HikariPool"],
        ),
        (
            "org.yaml",
            "snakeyaml",
            &["org.yaml.snakeyaml"],
            &[
                "Yaml",
                "DumperOptions",
                "LoaderOptions",
                "Constructor",
                "Representer",
            ],
        ),
        (
            "org.bouncycastle",
            "",
            &["org.bouncycastle"],
            &[
                "BCProvider",
                "KeyPairGenerator",
                "Signature",
                "Cipher",
                "MessageDigest",
                "SecretKey",
                "KeyFactory",
            ],
        ),
        (
            "io.circe",
            "",
            &["io.circe"],
            &[
                "Json",
                "Encoder",
                "Decoder",
                "Codec",
                "HCursor",
                "ACursor",
                "DecodingFailure",
                "ParsingFailure",
                "JsonObject",
            ],
        ),
        (
            "org.http4s",
            "",
            &["org.http4s"],
            &[
                "HttpRoutes",
                "Request",
                "Response",
                "Uri",
                "Status",
                "Headers",
                "EntityDecoder",
                "EntityEncoder",
            ],
        ),
        (
            "com.typesafe.slick",
            "",
            &["slick"],
            &[
                "Database",
                "DBIOAction",
                "DBIO",
                "TableQuery",
                "Table",
                "Column",
                "Rep",
                "Schema",
            ],
        ),
        (
            "io.getquill",
            "",
            &["io.getquill"],
            &[
                "QuillContext",
                "MysqlMonixJdbcContext",
                "PostgresJdbcContext",
                "quote",
                "query",
                "run",
            ],
        ),
        (
            "redis.clients",
            "jedis",
            &["redis.clients.jedis"],
            &[
                "Jedis",
                "JedisPool",
                "JedisPoolConfig",
                "Pipeline",
                "Transaction",
            ],
        ),
        (
            "com.redis",
            "",
            &["com.redis"],
            &["RedisClient", "RedisCommand"],
        ),
        (
            "org.apache.kafka",
            "",
            &["org.apache.kafka"],
            &[
                "KafkaProducer",
                "KafkaConsumer",
                "ProducerRecord",
                "ConsumerRecord",
                "KafkaAdminClient",
                "TopicPartition",
            ],
        ),
        (
            "com.stripe",
            "",
            &["com.stripe"],
            &[
                "Stripe",
                "Charge",
                "Customer",
                "PaymentIntent",
                "Subscription",
                "StripeClient",
                "PaymentMethod",
            ],
        ),
        (
            "org.mongodb",
            "",
            &["org.mongodb", "com.mongodb"],
            &[
                "MongoClient",
                "MongoDatabase",
                "MongoCollection",
                "Document",
                "BsonDocument",
                "MongoClients",
                "Filters",
                "Updates",
            ],
        ),
        (
            "org.elasticsearch",
            "",
            &["org.elasticsearch"],
            &[
                "RestHighLevelClient",
                "IndexRequest",
                "SearchRequest",
                "BulkRequest",
                "GetRequest",
            ],
        ),
        (
            "com.sendgrid",
            "",
            &["com.sendgrid"],
            &[
                "SendGrid",
                "Mail",
                "Email",
                "Personalization",
                "Content",
                "Attachments",
                "Response",
            ],
        ),
        (
            "com.twilio",
            "",
            &["com.twilio"],
            &["Twilio", "Message", "Call", "PhoneNumber"],
        ),
        (
            "javax.inject",
            "",
            &["javax.inject"],
            &[
                "Inject",
                "Named",
                "Singleton",
                "Provider",
                "Qualifier",
                "Scope",
            ],
        ),
        (
            "jakarta.inject",
            "",
            &["jakarta.inject"],
            &["Inject", "Named", "Singleton", "Provider"],
        ),
    ];

    for (porg, pname, pkgs, syms) in profiles {
        if org.contains(porg) && (pname.is_empty() || name.contains(pname)) {
            return DepProfile {
                packages: pkgs.to_vec(),
                symbols: syms.to_vec(),
            };
        }
    }

    // Fallback: derive package from org
    DepProfile {
        packages: vec![],
        symbols: vec![],
    }
}

fn is_runtime_only(org: &str, name: &str) -> bool {
    for (rorg, rname) in RUNTIME_PATTERNS {
        if org.contains(rorg) && (rname.is_empty() || name.contains(rname)) {
            return true;
        }
    }
    false
}

/// Represents what we found in a single source file
struct FileAnalysis {
    path: String,
    /// Which dep coords were imported
    imported_coords: HashSet<String>,
    /// Which dep coords had symbols found in body
    body_used_coords: HashMap<String, Vec<String>>, // coord → symbols found
}

/// Full deep usage scan: 3 passes per file
/// Pass 1: collect all imports
/// Pass 2: collect all body-level symbol references
/// Pass 3: cross-reference against dep profiles
pub fn scan_usage(root: &Path, deps: &[Dependency]) -> Result<Vec<DepUsageReport>> {
    // Build profile map for all deps
    let mut dep_profiles: Vec<(String, Dependency, DepProfile)> = Vec::new();
    for dep in deps {
        let profile = dep_profile(&dep.org, &dep.name);
        dep_profiles.push((dep.coord(), dep.clone(), profile));
    }

    let import_re = Regex::new(r"^\s*import\s+([\w.]+(?:\.\{[^}]+\}|\.\*|_)?)")?;
    // Body symbol regex: matches CamelCase identifiers (class names, objects)
    let symbol_re = Regex::new(r"\b([A-Z][a-zA-Z0-9]+)\b")?;

    let mut file_analyses: Vec<FileAnalysis> = Vec::new();

    for entry in WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let p = e.path();
            !p.components().any(|c| {
                let s = c.as_os_str().to_string_lossy();
                s == "target" || s == ".git" || s == ".metals" || s == ".bsp"
            }) && p
                .extension()
                .map_or(false, |ext| ext == "scala" || ext == "java")
        })
    {
        let path = entry.path();
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let mut analysis = FileAnalysis {
            path: path.to_string_lossy().to_string(),
            imported_coords: HashSet::new(),
            body_used_coords: HashMap::new(),
        };

        // Pass 1 & 2: split file into import section and body
        let mut import_lines: Vec<&str> = Vec::new();
        let mut body_lines: Vec<&str> = Vec::new();
        let mut past_package = false;

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("import ") {
                import_lines.push(line);
                past_package = true;
            } else if trimmed.starts_with("package ") {
                // ignore
            } else if past_package || (!trimmed.is_empty() && !trimmed.starts_with("//")) {
                past_package = true;
                body_lines.push(line);
            }
        }

        // Pass 1: match imports to dep profiles
        for line in &import_lines {
            if let Some(cap) = import_re.captures(line) {
                let import_path = cap[1].to_string();
                // Strip wildcard/block suffixes for prefix matching
                let clean = import_path
                    .split('{')
                    .next()
                    .unwrap_or(&import_path)
                    .trim_end_matches("._")
                    .trim_end_matches(".*")
                    .trim_end_matches('.')
                    .to_string();

                for (coord, _dep, profile) in &dep_profiles {
                    for pkg in &profile.packages {
                        if clean.starts_with(pkg) || pkg.starts_with(&clean as &str) {
                            analysis.imported_coords.insert(coord.clone());
                        }
                    }
                }
            }
        }

        // Pass 2: collect all CamelCase symbols from body
        let body_text = body_lines.join("\n");
        // Remove string literals and comments to avoid false matches
        let body_clean = strip_strings_and_comments(&body_text);
        let body_symbols: HashSet<String> = symbol_re
            .captures_iter(&body_clean)
            .map(|c| c[1].to_string())
            .collect();

        // Pass 3: match body symbols to dep profiles
        for (coord, _dep, profile) in &dep_profiles {
            let mut matched_syms: Vec<String> = profile
                .symbols
                .iter()
                .filter(|sym| body_symbols.contains(**sym))
                .map(|s| s.to_string())
                .collect();

            if !matched_syms.is_empty() {
                matched_syms.sort();
                matched_syms.dedup();
                analysis
                    .body_used_coords
                    .insert(coord.clone(), matched_syms);
            }
        }

        file_analyses.push(analysis);
    }

    // Aggregate per-dep
    let mut reports: Vec<DepUsageReport> = Vec::new();

    for (coord, dep, _profile) in &dep_profiles {
        // Skip transitive deps from usage report — focus on direct
        if dep.is_transitive {
            continue;
        }

        if is_runtime_only(&dep.org, &dep.name) {
            reports.push(DepUsageReport {
                coord: coord.clone(),
                version: dep.version.clone(),
                is_direct: true,
                verdict: UsageVerdict::RuntimeOnly,
                import_files: vec![],
                usage_files: vec![],
                symbols_found: vec![],
                usage_count: 0,
            });
            continue;
        }

        let import_files: Vec<String> = file_analyses
            .iter()
            .filter(|f| f.imported_coords.contains(coord))
            .map(|f| f.path.clone())
            .collect();

        let mut usage_files: Vec<String> = Vec::new();
        let mut all_symbols: HashSet<String> = HashSet::new();
        let mut total_usage = 0;

        for fa in &file_analyses {
            if let Some(syms) = fa.body_used_coords.get(coord) {
                usage_files.push(fa.path.clone());
                for s in syms {
                    all_symbols.insert(s.clone());
                }
                total_usage += syms.len();
            }
        }

        let mut symbols_found: Vec<String> = all_symbols.into_iter().collect();
        symbols_found.sort();

        let verdict = if !usage_files.is_empty() {
            UsageVerdict::Active
        } else if !import_files.is_empty() {
            UsageVerdict::DeadImport
        } else {
            UsageVerdict::Unused
        };

        reports.push(DepUsageReport {
            coord: coord.clone(),
            version: dep.version.clone(),
            is_direct: !dep.is_transitive,
            verdict,
            import_files,
            usage_files,
            symbols_found,
            usage_count: total_usage,
        });
    }

    // Sort: Unused first, then DeadImport, then Active, then Runtime
    reports.sort_by_key(|r| match r.verdict {
        UsageVerdict::Unused => 0,
        UsageVerdict::DeadImport => 1,
        UsageVerdict::Active => 2,
        UsageVerdict::RuntimeOnly => 3,
    });

    Ok(reports)
}

/// Strip string literals and line comments to reduce false symbol matches
fn strip_strings_and_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '/' if chars.peek() == Some(&'/') => {
                // Skip to end of line
                for c2 in chars.by_ref() {
                    if c2 == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            '"' => {
                // Skip string content
                for c2 in chars.by_ref() {
                    if c2 == '"' {
                        break;
                    }
                }
            }
            '\'' => {
                // Skip char literal
                for c2 in chars.by_ref() {
                    if c2 == '\'' {
                        break;
                    }
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// Original risky-dep-focused scanner (kept for backward compat)
pub fn scan_code_references(
    root: &Path,
    deps: &[Dependency],
) -> Result<HashMap<String, Vec<CodeReference>>> {
    let mut result: HashMap<String, Vec<CodeReference>> = HashMap::new();

    let mut package_map: Vec<(String, String)> = Vec::new();
    for dep in deps {
        let profile = dep_profile(&dep.org, &dep.name);
        for pkg in profile.packages {
            package_map.push((pkg.to_string(), dep.coord()));
        }
        // fallback
        if package_map.iter().all(|(_, c)| c != &dep.coord()) {
            package_map.push((dep.org.replace('-', "_"), dep.coord()));
        }
    }

    let import_re = Regex::new(r"^\s*import\s+([\w.]+)")?;

    for entry in WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let p = e.path();
            !p.components().any(|c| {
                let s = c.as_os_str().to_string_lossy();
                s == "target" || s == ".git" || s == ".metals"
            }) && p
                .extension()
                .map_or(false, |ext| ext == "scala" || ext == "java")
        })
    {
        let path = entry.path();
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for (line_num, line) in content.lines().enumerate() {
            if let Some(cap) = import_re.captures(line) {
                let import_path = &cap[1];
                for (pkg_prefix, dep_coord) in &package_map {
                    if import_path.starts_with(pkg_prefix.as_str()) {
                        let refs = result.entry(dep_coord.clone()).or_default();
                        refs.push(CodeReference {
                            dep_coord: dep_coord.clone(),
                            file: path.to_string_lossy().to_string(),
                            line_number: line_num + 1,
                            line_content: line.trim().to_string(),
                            import_path: import_path.to_string(),
                        });
                    }
                }
            }
        }
    }

    for refs in result.values_mut() {
        refs.dedup_by(|a, b| a.import_path == b.import_path && a.file == b.file);
        refs.truncate(10);
    }

    Ok(result)
}
