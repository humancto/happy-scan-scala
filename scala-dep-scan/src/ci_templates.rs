//! CI Template Generator
//!
//! Generates ready-to-use CI/CD configuration files for GitHub Actions and GitLab CI.
//! Self-contained — does not import from other project modules.

/// Generate a CI configuration template for the given platform.
///
/// Supported values: `"github"`, `"gitlab"`.
/// Returns the full YAML content as a string.
/// Returns an error message for unsupported platforms.
pub fn generate_ci_template(platform: &str) -> String {
    match platform.to_lowercase().as_str() {
        "github" => github_actions_template(),
        "gitlab" => gitlab_ci_template(),
        _ => format!(
            "Error: Unsupported CI platform '{}'. Supported: github, gitlab",
            platform
        ),
    }
}

fn github_actions_template() -> String {
    let mut t = String::new();
    t.push_str("# scala-dep-scan - Dependency Risk Scanner\n");
    t.push_str("# Add this file to .github/workflows/dep-scan.yml\n");
    t.push_str("\n");
    t.push_str("name: Dependency Risk Scan\n");
    t.push_str("\n");
    t.push_str("on:\n");
    t.push_str("  pull_request:\n");
    t.push_str("    branches: [main, master, develop]\n");
    t.push_str("    paths:\n");
    t.push_str("      - '**/build.sbt'\n");
    t.push_str("      - '**/project/**'\n");
    t.push_str("      - '**/build.properties'\n");
    t.push_str("  push:\n");
    t.push_str("    branches: [main, master]\n");
    t.push_str("  schedule:\n");
    t.push_str("    # Run weekly on Monday at 8am UTC\n");
    t.push_str("    - cron: '0 8 * * 1'\n");
    t.push_str("\n");
    t.push_str("permissions:\n");
    t.push_str("  contents: read\n");
    t.push_str("  pull-requests: write\n");
    t.push_str("\n");
    t.push_str("jobs:\n");
    t.push_str("  dep-scan:\n");
    t.push_str("    name: Scan Dependencies\n");
    t.push_str("    runs-on: ubuntu-latest\n");
    t.push_str("    steps:\n");
    t.push_str("      - name: Checkout code\n");
    t.push_str("        uses: actions/checkout@v4\n");
    t.push_str("\n");
    t.push_str("      - name: Download scala-dep-scan\n");
    t.push_str("        run: |\n");
    t.push_str("          LATEST=$(curl -s https://api.github.com/repos/ARC-RBRO/scala-dep-scan/releases/latest | grep tag_name | cut -d'\"' -f4)\n");
    t.push_str("          curl -sL \"https://github.com/ARC-RBRO/scala-dep-scan/releases/download/${LATEST}/scala-dep-scan-linux-amd64\" -o scala-dep-scan\n");
    t.push_str("          chmod +x scala-dep-scan\n");
    t.push_str("\n");
    t.push_str("      - name: Run dependency scan\n");
    t.push_str("        id: scan\n");
    t.push_str("        run: |\n");
    t.push_str("          # Run scan with JSON output for machine processing\n");
    t.push_str("          ./scala-dep-scan . --format json --osv --unused > scan-results.json 2>&1 || true\n");
    t.push_str("\n");
    t.push_str("          # Run scan with terminal output for the log\n");
    t.push_str("          echo \"## Scan Results\" >> $GITHUB_STEP_SUMMARY\n");
    t.push_str("          echo '```' >> $GITHUB_STEP_SUMMARY\n");
    t.push_str("          ./scala-dep-scan . --severity low --osv --unused 2>&1 | tee scan-output.txt >> $GITHUB_STEP_SUMMARY || true\n");
    t.push_str("          echo '```' >> $GITHUB_STEP_SUMMARY\n");
    t.push_str("\n");
    t.push_str("          # Generate HTML report\n");
    t.push_str(
        "          ./scala-dep-scan . --html scan-report.html --osv --unused 2>/dev/null || true\n",
    );
    t.push_str("\n");
    t.push_str("          # Save baseline for future comparisons\n");
    t.push_str(
        "          ./scala-dep-scan . --save-baseline baseline.json --osv 2>/dev/null || true\n",
    );
    t.push_str("\n");
    t.push_str("      - name: Compare with baseline (PR only)\n");
    t.push_str("        if: github.event_name == 'pull_request'\n");
    t.push_str("        id: diff\n");
    t.push_str("        run: |\n");
    t.push_str("          if [ -f \"baseline.json\" ]; then\n");
    t.push_str("            DIFF_OUTPUT=$(./scala-dep-scan . --compare baseline.json --osv 2>&1) || true\n");
    t.push_str("            echo \"diff_output<<EOF\" >> $GITHUB_OUTPUT\n");
    t.push_str("            echo \"$DIFF_OUTPUT\" >> $GITHUB_OUTPUT\n");
    t.push_str("            echo \"EOF\" >> $GITHUB_OUTPUT\n");
    t.push_str("          fi\n");
    t.push_str("\n");
    t.push_str("      - name: Comment on PR\n");
    t.push_str("        if: github.event_name == 'pull_request'\n");
    t.push_str("        uses: actions/github-script@v7\n");
    t.push_str("        with:\n");
    t.push_str("          script: |\n");
    t.push_str("            const fs = require('fs');\n");
    t.push_str("            let body = '## Dependency Risk Scan Results\\n\\n';\n");
    t.push_str("            try {\n");
    t.push_str("              const output = fs.readFileSync('scan-output.txt', 'utf8');\n");
    t.push_str("              body += '```\\n' + output.substring(0, 60000) + '\\n```\\n';\n");
    t.push_str("            } catch (e) {\n");
    t.push_str("              body += '_Scan output not available_\\n';\n");
    t.push_str("            }\n");
    t.push_str("            const diff = '${{ steps.diff.outputs.diff_output }}';\n");
    t.push_str("            if (diff) {\n");
    t.push_str(
        "              body += '\\n### Changes from Baseline\\n```\\n' + diff + '\\n```\\n';\n",
    );
    t.push_str("            }\n");
    t.push_str("            const { data: comments } = await github.rest.issues.listComments({\n");
    t.push_str("              owner: context.repo.owner,\n");
    t.push_str("              repo: context.repo.repo,\n");
    t.push_str("              issue_number: context.issue.number,\n");
    t.push_str("            });\n");
    t.push_str("            const existing = comments.find(c => c.body.includes('Dependency Risk Scan Results'));\n");
    t.push_str("            if (existing) {\n");
    t.push_str("              await github.rest.issues.updateComment({\n");
    t.push_str("                owner: context.repo.owner,\n");
    t.push_str("                repo: context.repo.repo,\n");
    t.push_str("                comment_id: existing.id,\n");
    t.push_str("                body: body,\n");
    t.push_str("              });\n");
    t.push_str("            } else {\n");
    t.push_str("              await github.rest.issues.createComment({\n");
    t.push_str("                owner: context.repo.owner,\n");
    t.push_str("                repo: context.repo.repo,\n");
    t.push_str("                issue_number: context.issue.number,\n");
    t.push_str("                body: body,\n");
    t.push_str("              });\n");
    t.push_str("            }\n");
    t.push_str("\n");
    t.push_str("      - name: Upload scan artifacts\n");
    t.push_str("        uses: actions/upload-artifact@v4\n");
    t.push_str("        if: always()\n");
    t.push_str("        with:\n");
    t.push_str("          name: dep-scan-results\n");
    t.push_str("          path: |\n");
    t.push_str("            scan-results.json\n");
    t.push_str("            scan-report.html\n");
    t.push_str("            baseline.json\n");
    t.push_str("          retention-days: 30\n");
    t.push_str("\n");
    t.push_str("      - name: Check for critical/high findings\n");
    t.push_str("        run: |\n");
    t.push_str("          # Exit with non-zero if critical or high findings exist\n");
    t.push_str("          EXIT_CODE=$(./scala-dep-scan . --severity high --format json --osv 2>/dev/null | grep -cE '\"severity\":\"Critical\"|\"severity\":\"High\"' || echo \"0\")\n");
    t.push_str("          if [ \"$EXIT_CODE\" -gt \"0\" ]; then\n");
    t.push_str("            echo \"::error::Found critical or high severity dependency risks\"\n");
    t.push_str("            exit 1\n");
    t.push_str("          fi\n");
    t
}

fn gitlab_ci_template() -> String {
    let mut t = String::new();
    t.push_str("# scala-dep-scan - Dependency Risk Scanner\n");
    t.push_str("# Add this to your .gitlab-ci.yml or include it\n");
    t.push_str("\n");
    t.push_str("stages:\n");
    t.push_str("  - security\n");
    t.push_str("\n");
    t.push_str("dependency-risk-scan:\n");
    t.push_str("  stage: security\n");
    t.push_str("  image: ubuntu:latest\n");
    t.push_str("  variables:\n");
    t.push_str("    SCAN_SEVERITY: \"low\"\n");
    t.push_str("  before_script:\n");
    t.push_str("    - apt-get update -qq && apt-get install -y -qq curl jq > /dev/null 2>&1\n");
    t.push_str("    - |\n");
    t.push_str("      LATEST=$(curl -s https://api.github.com/repos/ARC-RBRO/scala-dep-scan/releases/latest | jq -r .tag_name)\n");
    t.push_str("      curl -sL \"https://github.com/ARC-RBRO/scala-dep-scan/releases/download/${LATEST}/scala-dep-scan-linux-amd64\" -o /usr/local/bin/scala-dep-scan\n");
    t.push_str("      chmod +x /usr/local/bin/scala-dep-scan\n");
    t.push_str("  script:\n");
    t.push_str("    # Terminal output for the job log\n");
    t.push_str("    - scala-dep-scan . --severity $SCAN_SEVERITY --osv --unused 2>&1 | tee scan-output.txt || true\n");
    t.push_str("\n");
    t.push_str("    # JSON output for downstream processing\n");
    t.push_str(
        "    - scala-dep-scan . --format json --osv --unused > scan-results.json 2>&1 || true\n",
    );
    t.push_str("\n");
    t.push_str("    # HTML report\n");
    t.push_str(
        "    - scala-dep-scan . --html scan-report.html --osv --unused 2>/dev/null || true\n",
    );
    t.push_str("\n");
    t.push_str("    # Save baseline\n");
    t.push_str("    - scala-dep-scan . --save-baseline baseline.json --osv 2>/dev/null || true\n");
    t.push_str("\n");
    t.push_str("    # Fail on critical/high\n");
    t.push_str("    - |\n");
    t.push_str(
        "      if scala-dep-scan . --severity high --osv 2>&1 | grep -qE \"CRITICAL|HIGH\"; then\n",
    );
    t.push_str("        echo \"Found critical or high severity dependency risks\"\n");
    t.push_str("        exit 1\n");
    t.push_str("      fi\n");
    t.push_str("  artifacts:\n");
    t.push_str("    when: always\n");
    t.push_str("    paths:\n");
    t.push_str("      - scan-results.json\n");
    t.push_str("      - scan-report.html\n");
    t.push_str("      - scan-output.txt\n");
    t.push_str("      - baseline.json\n");
    t.push_str("    expire_in: 30 days\n");
    t.push_str("    reports:\n");
    t.push_str(
        "      # GitLab can parse the JSON for the security dashboard if formatted correctly\n",
    );
    t.push_str("      dependency_scanning: scan-results.json\n");
    t.push_str("  rules:\n");
    t.push_str("    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n");
    t.push_str("      changes:\n");
    t.push_str("        - \"**/build.sbt\"\n");
    t.push_str("        - \"**/project/**\"\n");
    t.push_str("    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'\n");
    t.push_str("    - if: '$CI_PIPELINE_SOURCE == \"schedule\"'\n");
    t.push_str("  allow_failure: false\n");
    t.push_str("\n");
    t.push_str("# Optional: Compare against baseline on merge requests\n");
    t.push_str("dependency-risk-diff:\n");
    t.push_str("  stage: security\n");
    t.push_str("  image: ubuntu:latest\n");
    t.push_str("  needs:\n");
    t.push_str("    - dependency-risk-scan\n");
    t.push_str("  before_script:\n");
    t.push_str("    - apt-get update -qq && apt-get install -y -qq curl jq > /dev/null 2>&1\n");
    t.push_str("    - |\n");
    t.push_str("      LATEST=$(curl -s https://api.github.com/repos/ARC-RBRO/scala-dep-scan/releases/latest | jq -r .tag_name)\n");
    t.push_str("      curl -sL \"https://github.com/ARC-RBRO/scala-dep-scan/releases/download/${LATEST}/scala-dep-scan-linux-amd64\" -o /usr/local/bin/scala-dep-scan\n");
    t.push_str("      chmod +x /usr/local/bin/scala-dep-scan\n");
    t.push_str("  script:\n");
    t.push_str("    - |\n");
    t.push_str("      if [ -f baseline.json ]; then\n");
    t.push_str(
        "        scala-dep-scan . --compare baseline.json --osv 2>&1 | tee diff-output.txt\n",
    );
    t.push_str("      else\n");
    t.push_str("        echo \"No baseline found, skipping comparison\"\n");
    t.push_str("      fi\n");
    t.push_str("  artifacts:\n");
    t.push_str("    when: always\n");
    t.push_str("    paths:\n");
    t.push_str("      - diff-output.txt\n");
    t.push_str("    expire_in: 7 days\n");
    t.push_str("  rules:\n");
    t.push_str("    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n");
    t.push_str("  allow_failure: true\n");
    t
}

/// List all supported CI platforms.
pub fn supported_platforms() -> Vec<&'static str> {
    vec!["github", "gitlab"]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_github_template_valid() {
        let t = generate_ci_template("github");
        assert!(t.contains("name: Dependency Risk Scan"));
        assert!(t.contains("actions/checkout@v4"));
        assert!(t.contains("scala-dep-scan"));
        assert!(t.contains("upload-artifact"));
    }

    #[test]
    fn test_gitlab_template_valid() {
        let t = generate_ci_template("gitlab");
        assert!(t.contains("stages:"));
        assert!(t.contains("dependency-risk-scan:"));
        assert!(t.contains("scala-dep-scan"));
        assert!(t.contains("artifacts:"));
    }

    #[test]
    fn test_case_insensitive() {
        let t = generate_ci_template("GitHub");
        assert!(t.contains("name: Dependency Risk Scan"));
    }

    #[test]
    fn test_unsupported_platform() {
        let t = generate_ci_template("jenkins");
        assert!(t.contains("Error: Unsupported CI platform"));
    }
}
