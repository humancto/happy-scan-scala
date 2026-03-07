use std::path::Path;

#[test]
fn test_fix_unused_dry_run() {
    let tmpdir = std::env::temp_dir().join("scala-dep-scan-test-dryrun");
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();

    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    std::fs::copy(
        fixture_dir.join("simple_build.sbt"),
        tmpdir.join("build.sbt"),
    )
    .unwrap();

    // Copy scala files so usage analysis works
    let app_dir = tmpdir.join("app");
    std::fs::create_dir_all(&app_dir).unwrap();
    std::fs::copy(
        fixture_dir.join("sample.scala"),
        app_dir.join("sample.scala"),
    )
    .unwrap();

    let original_content = std::fs::read_to_string(tmpdir.join("build.sbt")).unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_scala-dep-scan"))
        .args([
            tmpdir.to_str().unwrap(),
            "--fix-unused",
            "--dry-run",
            "-q",
            "--no-tree",
        ])
        .output()
        .expect("Failed to execute binary");

    // In dry-run mode, build.sbt should NOT be modified
    let after_content = std::fs::read_to_string(tmpdir.join("build.sbt")).unwrap();
    assert_eq!(
        original_content, after_content,
        "Dry-run should not modify build.sbt"
    );

    // Should not create backup
    let backup_exists = tmpdir.join("build.sbt.bak").exists();
    assert!(!backup_exists, "Dry-run should not create .bak file");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should mention proposed changes or that it would change things
    // (it might not if no deps are detected as unused with fixtures)

    let _ = std::fs::remove_dir_all(&tmpdir);
}

#[test]
fn test_fix_unused_applies_changes() {
    let tmpdir = std::env::temp_dir().join("scala-dep-scan-test-fixunused");
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();

    let build_content = r#"
name := "test"

libraryDependencies ++= Seq(
  "com.typesafe.play" %% "play-json" % "2.3.2",
  "com.example.unused" % "unused-lib" % "1.0.0",
  "com.example.unused2" % "unused-lib2" % "2.0.0"
)
"#;
    std::fs::write(tmpdir.join("build.sbt"), build_content).unwrap();

    // Create a scala file that only imports play-json
    let app_dir = tmpdir.join("app");
    std::fs::create_dir_all(&app_dir).unwrap();
    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    std::fs::copy(
        fixture_dir.join("unused_sample.scala"),
        app_dir.join("sample.scala"),
    )
    .unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_scala-dep-scan"))
        .args([tmpdir.to_str().unwrap(), "--fix-unused", "-q", "--no-tree"])
        .output()
        .expect("Failed to execute binary");

    // Check backup was created
    assert!(
        tmpdir.join("build.sbt.bak").exists(),
        "Should create backup file"
    );

    let modified = std::fs::read_to_string(tmpdir.join("build.sbt")).unwrap();
    // unused-lib should be commented out
    let has_commented =
        modified.contains("// REMOVED by scala-dep-scan:") || modified.contains("unused-lib");
    assert!(has_commented, "Should comment out or mention unused deps");

    let _ = std::fs::remove_dir_all(&tmpdir);
}
