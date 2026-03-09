// Phase 4: Interactive TUI Explorer for scala-dep-scan
// This module provides a full-featured terminal UI using ratatui + crossterm.
//
// Entry point: `run_tui(report_json: &str)` which takes the JSON report
// (same format as `--format json` output) and launches an interactive explorer.
//
// All types are defined locally to avoid modifying types.rs.

use std::io;
use std::time::Duration;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};
use serde::Deserialize;
use std::collections::HashMap;

// ──────────────────────────────────────────────────────────────
// Local types mirroring the JSON report structure
// ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
struct JDependency {
    org: String,
    name: String,
    version: String,
    scope: Option<String>,
    cross_compiled: bool,
    source_file: String,
    is_transitive: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct JRiskFlag {
    dependency: JDependency,
    severity: JSeverity,
    reason: String,
    cve_ids: Vec<String>,
    risk_type: JRiskType,
    fix_suggestion: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, PartialOrd, Ord, Copy)]
enum JSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl JSeverity {
    fn label(&self) -> &str {
        match self {
            JSeverity::Info => "INFO",
            JSeverity::Low => "LOW",
            JSeverity::Medium => "MEDIUM",
            JSeverity::High => "HIGH",
            JSeverity::Critical => "CRITICAL",
        }
    }

    fn color(&self) -> Color {
        match self {
            JSeverity::Critical => Color::Red,
            JSeverity::High => Color::Rgb(200, 80, 0),
            JSeverity::Medium => Color::Yellow,
            JSeverity::Low => Color::Green,
            JSeverity::Info => Color::Blue,
        }
    }

    fn icon(&self) -> &str {
        match self {
            JSeverity::Critical => "[!!]",
            JSeverity::High => "[! ]",
            JSeverity::Medium => "[~ ]",
            JSeverity::Low => "[. ]",
            JSeverity::Info => "[i ]",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
enum JRiskType {
    KnownVulnerable,
    Outdated,
    OsvAdvisory,
}

impl JRiskType {
    fn label(&self) -> &str {
        match self {
            JRiskType::KnownVulnerable => "KNOWN-CVE",
            JRiskType::Outdated => "OUTDATED",
            JRiskType::OsvAdvisory => "OSV-ADVISORY",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct JCodeReference {
    dep_coord: String,
    file: String,
    line_number: usize,
    line_content: String,
    import_path: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
enum JUsageVerdict {
    Active,
    DeadImport,
    Unused,
    RuntimeOnly,
}

impl JUsageVerdict {
    fn label(&self) -> &str {
        match self {
            JUsageVerdict::Active => "ACTIVE",
            JUsageVerdict::DeadImport => "DEAD IMPORT",
            JUsageVerdict::Unused => "UNUSED",
            JUsageVerdict::RuntimeOnly => "RUNTIME",
        }
    }

    fn color(&self) -> Color {
        match self {
            JUsageVerdict::Active => Color::Green,
            JUsageVerdict::DeadImport => Color::Yellow,
            JUsageVerdict::Unused => Color::Red,
            JUsageVerdict::RuntimeOnly => Color::DarkGray,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct JDepUsageReport {
    coord: String,
    version: String,
    is_direct: bool,
    verdict: JUsageVerdict,
    import_files: Vec<String>,
    usage_files: Vec<String>,
    symbols_found: Vec<String>,
    usage_count: usize,
}

#[derive(Debug, Deserialize)]
struct JSummary {
    direct_deps: usize,
    transitive_deps: usize,
    total_flags: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
}

#[derive(Debug, Deserialize)]
struct JReport {
    summary: JSummary,
    risk_flags: Vec<JRiskFlag>,
    code_references: HashMap<String, Vec<JCodeReference>>,
    #[serde(default)]
    usage_reports: Vec<JDepUsageReport>,
}

// ──────────────────────────────────────────────────────────────
// TUI domain model
// ──────────────────────────────────────────────────────────────

/// A unified dependency entry for TUI display, combining risk + usage data.
#[derive(Debug, Clone)]
struct TuiDep {
    coord: String, // e.g. "com.typesafe.play:play-json"
    version: String,
    severity: Option<JSeverity>,
    risk_flags: Vec<TuiRiskEntry>,
    usage: Option<TuiUsageEntry>,
    code_refs: Vec<JCodeReference>,
    is_transitive: bool,
    source_file: String,
    scope: Option<String>,
}

#[derive(Debug, Clone)]
struct TuiRiskEntry {
    severity: JSeverity,
    risk_type_label: String,
    reason: String,
    cve_ids: Vec<String>,
    fix_suggestion: Option<String>,
}

#[derive(Debug, Clone)]
struct TuiUsageEntry {
    verdict: JUsageVerdict,
    symbols_found: Vec<String>,
    usage_count: usize,
    import_files: Vec<String>,
    usage_files: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Panel {
    Left,
    Right,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum FilterMode {
    All,
    Critical,
    High,
    Medium,
    Low,
    Unused,
}

impl FilterMode {
    fn label(&self) -> &str {
        match self {
            FilterMode::All => "All",
            FilterMode::Critical => "Critical",
            FilterMode::High => "High",
            FilterMode::Medium => "Medium",
            FilterMode::Low => "Low",
            FilterMode::Unused => "Unused",
        }
    }

    fn next(&self) -> FilterMode {
        match self {
            FilterMode::All => FilterMode::Critical,
            FilterMode::Critical => FilterMode::High,
            FilterMode::High => FilterMode::Medium,
            FilterMode::Medium => FilterMode::Low,
            FilterMode::Low => FilterMode::Unused,
            FilterMode::Unused => FilterMode::All,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum SortMode {
    Severity,
    Name,
    Usage,
    Version,
}

impl SortMode {
    fn label(&self) -> &str {
        match self {
            SortMode::Severity => "Severity",
            SortMode::Name => "Name",
            SortMode::Usage => "Usage",
            SortMode::Version => "Version",
        }
    }

    fn next(&self) -> SortMode {
        match self {
            SortMode::Severity => SortMode::Name,
            SortMode::Name => SortMode::Usage,
            SortMode::Usage => SortMode::Version,
            SortMode::Version => SortMode::Severity,
        }
    }
}

struct TuiState {
    deps: Vec<TuiDep>,
    filtered_indices: Vec<usize>,
    selected_index: usize,
    active_panel: Panel,
    filter_mode: FilterMode,
    sort_mode: SortMode,
    search_query: String,
    is_searching: bool,
    list_state: ListState,
    scroll_offset: u16, // vertical scroll for detail panel
    summary: JSummary,
    status_message: Option<String>,
}

impl TuiState {
    fn selected_dep(&self) -> Option<&TuiDep> {
        self.filtered_indices
            .get(self.selected_index)
            .and_then(|&idx| self.deps.get(idx))
    }

    fn refilter(&mut self) {
        self.filtered_indices = (0..self.deps.len())
            .filter(|&i| {
                let dep = &self.deps[i];

                // Filter mode
                let passes_filter = match self.filter_mode {
                    FilterMode::All => true,
                    FilterMode::Critical => dep.severity == Some(JSeverity::Critical),
                    FilterMode::High => dep.severity.map_or(false, |s| s >= JSeverity::High),
                    FilterMode::Medium => dep.severity.map_or(false, |s| s >= JSeverity::Medium),
                    FilterMode::Low => dep.severity.map_or(false, |s| s >= JSeverity::Low),
                    FilterMode::Unused => dep.usage.as_ref().map_or(false, |u| {
                        u.verdict == JUsageVerdict::Unused || u.verdict == JUsageVerdict::DeadImport
                    }),
                };

                // Search query
                let passes_search = if self.search_query.is_empty() {
                    true
                } else {
                    let q = self.search_query.to_lowercase();
                    dep.coord.to_lowercase().contains(&q) || dep.version.to_lowercase().contains(&q)
                };

                passes_filter && passes_search
            })
            .collect();

        self.resort();

        // Clamp selected index
        if self.filtered_indices.is_empty() {
            self.selected_index = 0;
        } else if self.selected_index >= self.filtered_indices.len() {
            self.selected_index = self.filtered_indices.len() - 1;
        }
        self.list_state.select(Some(self.selected_index));
        self.scroll_offset = 0;
    }

    fn resort(&mut self) {
        let deps = &self.deps;
        let sort_mode = self.sort_mode;
        self.filtered_indices.sort_by(|&a, &b| {
            let da = &deps[a];
            let db = &deps[b];
            match sort_mode {
                SortMode::Severity => {
                    let sa = da.severity.unwrap_or(JSeverity::Info);
                    let sb = db.severity.unwrap_or(JSeverity::Info);
                    sb.cmp(&sa) // descending
                }
                SortMode::Name => da.coord.cmp(&db.coord),
                SortMode::Usage => {
                    let ua = da.usage.as_ref().map_or(0, |u| u.usage_count);
                    let ub = db.usage.as_ref().map_or(0, |u| u.usage_count);
                    ub.cmp(&ua)
                }
                SortMode::Version => da.version.cmp(&db.version),
            }
        });
    }

    fn move_up(&mut self) {
        if !self.filtered_indices.is_empty() && self.selected_index > 0 {
            self.selected_index -= 1;
            self.list_state.select(Some(self.selected_index));
            self.scroll_offset = 0;
        }
    }

    fn move_down(&mut self) {
        if !self.filtered_indices.is_empty()
            && self.selected_index + 1 < self.filtered_indices.len()
        {
            self.selected_index += 1;
            self.list_state.select(Some(self.selected_index));
            self.scroll_offset = 0;
        }
    }
}

// ──────────────────────────────────────────────────────────────
// Data loading
// ──────────────────────────────────────────────────────────────

fn build_tui_deps(report: JReport) -> (Vec<TuiDep>, JSummary) {
    let mut dep_map: HashMap<String, TuiDep> = HashMap::new();

    // Build from risk_flags
    for flag in &report.risk_flags {
        let d = &flag.dependency;
        let coord = format!("{}:{}", d.org, d.name);
        let entry = dep_map.entry(coord.clone()).or_insert_with(|| TuiDep {
            coord: coord.clone(),
            version: d.version.clone(),
            severity: None,
            risk_flags: Vec::new(),
            usage: None,
            code_refs: Vec::new(),
            is_transitive: d.is_transitive,
            source_file: d.source_file.clone(),
            scope: d.scope.clone(),
        });

        let risk_entry = TuiRiskEntry {
            severity: flag.severity,
            risk_type_label: flag.risk_type.label().to_string(),
            reason: flag.reason.clone(),
            cve_ids: flag.cve_ids.clone(),
            fix_suggestion: flag.fix_suggestion.clone(),
        };

        // Update max severity
        let new_sev = flag.severity;
        entry.severity = Some(match entry.severity {
            Some(existing) if existing >= new_sev => existing,
            _ => new_sev,
        });
        entry.risk_flags.push(risk_entry);
    }

    // Attach code references
    for (coord, refs) in &report.code_references {
        if let Some(entry) = dep_map.get_mut(coord) {
            entry.code_refs = refs.clone();
        } else {
            // code_ref for a dep not in risk_flags — create entry
            let entry = TuiDep {
                coord: coord.clone(),
                version: String::new(),
                severity: None,
                risk_flags: Vec::new(),
                usage: None,
                code_refs: refs.clone(),
                is_transitive: false,
                source_file: String::new(),
                scope: None,
            };
            dep_map.insert(coord.clone(), entry);
        }
    }

    // Attach usage reports
    for ur in &report.usage_reports {
        let entry = dep_map.entry(ur.coord.clone()).or_insert_with(|| TuiDep {
            coord: ur.coord.clone(),
            version: ur.version.clone(),
            severity: None,
            risk_flags: Vec::new(),
            usage: None,
            code_refs: Vec::new(),
            is_transitive: !ur.is_direct,
            source_file: String::new(),
            scope: None,
        });
        if entry.version.is_empty() {
            entry.version = ur.version.clone();
        }
        entry.usage = Some(TuiUsageEntry {
            verdict: ur.verdict.clone(),
            symbols_found: ur.symbols_found.clone(),
            usage_count: ur.usage_count,
            import_files: ur.import_files.clone(),
            usage_files: ur.usage_files.clone(),
        });
    }

    let mut deps: Vec<TuiDep> = dep_map.into_values().collect();
    // Default sort: severity descending, then name
    deps.sort_by(|a, b| {
        let sa = a.severity.unwrap_or(JSeverity::Info);
        let sb = b.severity.unwrap_or(JSeverity::Info);
        sb.cmp(&sa).then_with(|| a.coord.cmp(&b.coord))
    });

    (deps, report.summary)
}

// ──────────────────────────────────────────────────────────────
// Public entry point
// ──────────────────────────────────────────────────────────────

pub fn run_tui(report_json: &str) -> Result<(), Box<dyn std::error::Error>> {
    let report: JReport = serde_json::from_str(report_json)?;
    let (deps, summary) = build_tui_deps(report);

    let total = deps.len();
    let all_indices: Vec<usize> = (0..total).collect();

    let mut state = TuiState {
        deps,
        filtered_indices: all_indices,
        selected_index: 0,
        active_panel: Panel::Left,
        filter_mode: FilterMode::All,
        sort_mode: SortMode::Severity,
        search_query: String::new(),
        is_searching: false,
        list_state: ListState::default(),
        scroll_offset: 0,
        summary,
        status_message: None,
    };
    state.list_state.select(Some(0));

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_event_loop(&mut terminal, &mut state);

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut TuiState,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        terminal.draw(|f| draw_ui(f, state))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                // Ctrl+C always quits
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    return Ok(());
                }

                if state.is_searching {
                    match key.code {
                        KeyCode::Esc => {
                            state.is_searching = false;
                            state.search_query.clear();
                            state.refilter();
                        }
                        KeyCode::Enter => {
                            state.is_searching = false;
                            // keep the filter active
                        }
                        KeyCode::Backspace => {
                            state.search_query.pop();
                            state.refilter();
                        }
                        KeyCode::Char(c) => {
                            state.search_query.push(c);
                            state.refilter();
                        }
                        _ => {}
                    }
                    continue;
                }

                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Up | KeyCode::Char('k') => state.move_up(),
                    KeyCode::Down | KeyCode::Char('j') => state.move_down(),
                    KeyCode::Tab => {
                        state.active_panel = match state.active_panel {
                            Panel::Left => Panel::Right,
                            Panel::Right => Panel::Left,
                        };
                    }
                    KeyCode::Char('/') => {
                        state.is_searching = true;
                        state.search_query.clear();
                    }
                    KeyCode::Char('f') => {
                        state.filter_mode = state.filter_mode.next();
                        state.refilter();
                    }
                    KeyCode::Char('s') => {
                        state.sort_mode = state.sort_mode.next();
                        state.refilter();
                        state.status_message = Some(format!("Sort: {}", state.sort_mode.label()));
                    }
                    KeyCode::Char('e') => {
                        export_current_view(state);
                        state.status_message =
                            Some("Exported to scala-dep-scan-export.json".to_string());
                    }
                    // Scroll detail panel
                    KeyCode::PageDown | KeyCode::Char('d') => {
                        if state.active_panel == Panel::Right {
                            state.scroll_offset = state.scroll_offset.saturating_add(5);
                        }
                    }
                    KeyCode::PageUp | KeyCode::Char('u') => {
                        if state.active_panel == Panel::Right {
                            state.scroll_offset = state.scroll_offset.saturating_sub(5);
                        }
                    }
                    KeyCode::Home | KeyCode::Char('g') => {
                        if state.active_panel == Panel::Left {
                            state.selected_index = 0;
                            state.list_state.select(Some(0));
                            state.scroll_offset = 0;
                        }
                    }
                    KeyCode::End | KeyCode::Char('G') => {
                        if state.active_panel == Panel::Left && !state.filtered_indices.is_empty() {
                            state.selected_index = state.filtered_indices.len() - 1;
                            state.list_state.select(Some(state.selected_index));
                            state.scroll_offset = 0;
                        }
                    }
                    _ => {}
                }
            }
            if let Event::Resize(_, _) = event::read().unwrap_or(Event::FocusGained) {
                // Terminal will redraw on next iteration
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────
// Rendering
// ──────────────────────────────────────────────────────────────

fn draw_ui(f: &mut Frame, state: &mut TuiState) {
    let size = f.size();

    // Main layout: header, body, footer
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(10),   // body
            Constraint::Length(3), // footer
        ])
        .split(size);

    draw_header(f, main_chunks[0], state);
    draw_body(f, main_chunks[1], state);
    draw_footer(f, main_chunks[2], state);
}

fn draw_header(f: &mut Frame, area: Rect, state: &TuiState) {
    let s = &state.summary;
    let header_text = vec![Line::from(vec![
        Span::styled(
            " scala-dep-scan TUI Explorer ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            format!(
                "{} deps | {}C {}H {}M {}L flags",
                s.direct_deps + s.transitive_deps,
                s.critical,
                s.high,
                s.medium,
                s.low
            ),
            Style::default().fg(Color::DarkGray),
        ),
    ])];

    let header = Paragraph::new(header_text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title(" scala-dep-scan ")
            .title_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
    );
    f.render_widget(header, area);
}

fn draw_body(f: &mut Frame, area: Rect, state: &mut TuiState) {
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(area);

    draw_dep_list(f, body_chunks[0], state);
    draw_detail_panel(f, body_chunks[1], state);
}

fn draw_dep_list(f: &mut Frame, area: Rect, state: &mut TuiState) {
    let border_color = if state.active_panel == Panel::Left {
        Color::Cyan
    } else {
        Color::DarkGray
    };

    let filter_label = format!(
        " Dependencies ({}) [Filter: {}] [Sort: {}] ",
        state.filtered_indices.len(),
        state.filter_mode.label(),
        state.sort_mode.label()
    );

    let items: Vec<ListItem> = state
        .filtered_indices
        .iter()
        .map(|&idx| {
            let dep = &state.deps[idx];
            let icon = match &dep.severity {
                Some(JSeverity::Critical) => ("[!!]", Color::Red),
                Some(JSeverity::High) => ("[! ]", Color::Rgb(200, 80, 0)),
                Some(JSeverity::Medium) => ("[~ ]", Color::Yellow),
                Some(JSeverity::Low) => ("[. ]", Color::Green),
                _ => {
                    // Use usage verdict icon if no risk
                    match dep.usage.as_ref().map(|u| &u.verdict) {
                        Some(JUsageVerdict::Unused) => ("[x ]", Color::Red),
                        Some(JUsageVerdict::DeadImport) => ("[~ ]", Color::Yellow),
                        Some(JUsageVerdict::Active) => ("[ok]", Color::Green),
                        Some(JUsageVerdict::RuntimeOnly) => ("[rt]", Color::DarkGray),
                        None => ("[  ]", Color::DarkGray),
                    }
                }
            };

            // Short name: take last part of org + name
            let short_name = format_short_name(&dep.coord);
            let display = format!("{} {}:{}", icon.0, short_name, dep.version);

            ListItem::new(Line::from(vec![Span::styled(
                display,
                Style::default().fg(icon.1),
            )]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color))
                .title(filter_label)
                .title_style(
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
        )
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::REVERSED)
                .fg(Color::White),
        )
        .highlight_symbol("> ");

    f.render_stateful_widget(list, area, &mut state.list_state);
}

fn draw_detail_panel(f: &mut Frame, area: Rect, state: &TuiState) {
    let border_color = if state.active_panel == Panel::Right {
        Color::Cyan
    } else {
        Color::DarkGray
    };

    let dep = match state.selected_dep() {
        Some(d) => d,
        None => {
            let empty = Paragraph::new("No dependency selected").block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(border_color))
                    .title(" Detail View "),
            );
            f.render_widget(empty, area);
            return;
        }
    };

    let mut lines: Vec<Line> = Vec::new();

    // Dependency header
    lines.push(Line::from(vec![
        Span::styled(
            &dep.coord,
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(":"),
        Span::styled(&dep.version, Style::default().fg(Color::Cyan)),
    ]));
    lines.push(Line::from(""));

    // Source info
    if !dep.source_file.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("Source:    ", Style::default().fg(Color::DarkGray)),
            Span::raw(shorten_path(&dep.source_file)),
        ]));
    }
    if let Some(scope) = &dep.scope {
        lines.push(Line::from(vec![
            Span::styled("Scope:     ", Style::default().fg(Color::DarkGray)),
            Span::raw(scope.as_str()),
        ]));
    }
    lines.push(Line::from(vec![
        Span::styled("Type:      ", Style::default().fg(Color::DarkGray)),
        Span::raw(if dep.is_transitive {
            "Transitive"
        } else {
            "Direct"
        }),
    ]));
    lines.push(Line::from(""));

    // Risk information
    if !dep.risk_flags.is_empty() {
        lines.push(Line::from(Span::styled(
            "--- Risk Analysis ---",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));

        for rf in &dep.risk_flags {
            let sev_color = rf.severity.color();
            lines.push(Line::from(vec![
                Span::styled("Risk:      ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    rf.severity.label(),
                    Style::default()
                        .fg(Color::White)
                        .bg(sev_color)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Type:      ", Style::default().fg(Color::DarkGray)),
                Span::styled(&rf.risk_type_label, Style::default().fg(sev_color)),
            ]));

            if !rf.cve_ids.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("CVEs:      ", Style::default().fg(Color::DarkGray)),
                    Span::styled(rf.cve_ids.join(", "), Style::default().fg(Color::Yellow)),
                ]));
            }

            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("Reason:    ", Style::default().fg(Color::DarkGray)),
                Span::raw(&rf.reason),
            ]));

            if let Some(fix) = &rf.fix_suggestion {
                lines.push(Line::from(vec![
                    Span::styled(
                        "Fix:       ",
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(fix.as_str(), Style::default().fg(Color::Green)),
                ]));
            }
            lines.push(Line::from(""));
        }
    } else {
        lines.push(Line::from(Span::styled(
            "No risk flags",
            Style::default().fg(Color::Green),
        )));
        lines.push(Line::from(""));
    }

    // Usage information
    if let Some(usage) = &dep.usage {
        lines.push(Line::from(Span::styled(
            "--- Usage Analysis ---",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));

        lines.push(Line::from(vec![
            Span::styled("Usage:     ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{} ({} refs)", usage.verdict.label(), usage.usage_count),
                Style::default().fg(usage.verdict.color()),
            ),
        ]));

        if !usage.symbols_found.is_empty() {
            let sym_display: String = usage
                .symbols_found
                .iter()
                .take(8)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            let more = if usage.symbols_found.len() > 8 {
                format!(" +{} more", usage.symbols_found.len() - 8)
            } else {
                String::new()
            };
            lines.push(Line::from(vec![
                Span::styled("Symbols:   ", Style::default().fg(Color::DarkGray)),
                Span::raw(format!("{}{}", sym_display, more)),
            ]));
        }

        if !usage.import_files.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!("Import Files ({}):", usage.import_files.len()),
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::UNDERLINED),
            )));
            for f in usage.import_files.iter().take(10) {
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(shorten_path(f), Style::default().fg(Color::Cyan)),
                ]));
            }
            if usage.import_files.len() > 10 {
                lines.push(Line::from(Span::styled(
                    format!("  ... and {} more", usage.import_files.len() - 10),
                    Style::default().fg(Color::DarkGray),
                )));
            }
        }

        if !usage.usage_files.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!("Usage Files ({}):", usage.usage_files.len()),
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::UNDERLINED),
            )));
            for f in usage.usage_files.iter().take(10) {
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(shorten_path(f), Style::default().fg(Color::Green)),
                ]));
            }
            if usage.usage_files.len() > 10 {
                lines.push(Line::from(Span::styled(
                    format!("  ... and {} more", usage.usage_files.len() - 10),
                    Style::default().fg(Color::DarkGray),
                )));
            }
        }

        lines.push(Line::from(""));
    }

    // Code references
    if !dep.code_refs.is_empty() {
        lines.push(Line::from(Span::styled(
            "--- Code References ---",
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));

        for cr in dep.code_refs.iter().take(20) {
            let short = shorten_path(&cr.file);
            lines.push(Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(
                    format!("{}:{}", short, cr.line_number),
                    Style::default().fg(Color::Cyan),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::raw("    "),
                Span::styled(&cr.import_path, Style::default().fg(Color::DarkGray)),
            ]));
        }
        if dep.code_refs.len() > 20 {
            lines.push(Line::from(Span::styled(
                format!("  ... and {} more references", dep.code_refs.len() - 20),
                Style::default().fg(Color::DarkGray),
            )));
        }
    }

    // Apply scroll offset
    let scroll = state.scroll_offset as usize;
    let visible_lines = if scroll < lines.len() {
        lines[scroll..].to_vec()
    } else {
        vec![Line::from(Span::styled(
            "(end of content)",
            Style::default().fg(Color::DarkGray),
        ))]
    };

    let detail = Paragraph::new(visible_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color))
                .title(" Detail View ")
                .title_style(
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
        )
        .wrap(Wrap { trim: false });

    f.render_widget(detail, area);
}

fn draw_footer(f: &mut Frame, area: Rect, state: &TuiState) {
    let lines = if state.is_searching {
        vec![Line::from(vec![
            Span::styled(
                " Search: ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(&state.search_query, Style::default().fg(Color::Yellow)),
            Span::styled(
                "_",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::SLOW_BLINK),
            ),
            Span::styled(
                "  [Enter] confirm  [Esc] cancel",
                Style::default().fg(Color::DarkGray),
            ),
        ])]
    } else if let Some(msg) = &state.status_message {
        vec![Line::from(vec![
            Span::styled(format!(" {} ", msg), Style::default().fg(Color::Green)),
            Span::raw("  "),
            Span::styled(
                "[q]uit  [/]search  [f]ilter  [s]ort  [e]xport  [Tab]panel  [j/k]nav",
                Style::default().fg(Color::DarkGray),
            ),
        ])]
    } else {
        vec![Line::from(vec![
            Span::styled(
                " [q] ",
                Style::default().fg(Color::Black).bg(Color::DarkGray),
            ),
            Span::styled("Quit ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                " [/] ",
                Style::default().fg(Color::Black).bg(Color::DarkGray),
            ),
            Span::styled("Search ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                " [f] ",
                Style::default().fg(Color::Black).bg(Color::DarkGray),
            ),
            Span::styled("Filter ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                " [s] ",
                Style::default().fg(Color::Black).bg(Color::DarkGray),
            ),
            Span::styled("Sort ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                " [e] ",
                Style::default().fg(Color::Black).bg(Color::DarkGray),
            ),
            Span::styled("Export ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                " [Tab] ",
                Style::default().fg(Color::Black).bg(Color::DarkGray),
            ),
            Span::styled("Panel ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                " [j/k] ",
                Style::default().fg(Color::Black).bg(Color::DarkGray),
            ),
            Span::styled("Navigate", Style::default().fg(Color::DarkGray)),
        ])]
    };

    let footer = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(footer, area);
}

// ──────────────────────────────────────────────────────────────
// Utilities
// ──────────────────────────────────────────────────────────────

fn shorten_path(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() > 3 {
        format!(".../{}", parts[parts.len() - 3..].join("/"))
    } else {
        path.to_string()
    }
}

fn format_short_name(coord: &str) -> String {
    // "com.typesafe.play:play-json" -> "play-json"
    if let Some((_org, name)) = coord.split_once(':') {
        name.to_string()
    } else {
        coord.to_string()
    }
}

fn export_current_view(state: &TuiState) {
    let export: Vec<serde_json::Value> = state
        .filtered_indices
        .iter()
        .map(|&idx| {
            let dep = &state.deps[idx];
            serde_json::json!({
                "coord": dep.coord,
                "version": dep.version,
                "severity": dep.severity.map(|s| s.label().to_string()),
                "is_transitive": dep.is_transitive,
                "risk_count": dep.risk_flags.len(),
                "cve_ids": dep.risk_flags.iter()
                    .flat_map(|r| r.cve_ids.iter().cloned())
                    .collect::<Vec<_>>(),
                "usage_verdict": dep.usage.as_ref().map(|u| u.verdict.label()),
                "usage_count": dep.usage.as_ref().map(|u| u.usage_count).unwrap_or(0),
                "code_ref_count": dep.code_refs.len(),
            })
        })
        .collect();

    let json = serde_json::json!({
        "exported_at": chrono_now_fallback(),
        "filter": state.filter_mode.label(),
        "sort": state.sort_mode.label(),
        "search_query": state.search_query,
        "total_shown": export.len(),
        "dependencies": export,
    });

    let _ = std::fs::write(
        "scala-dep-scan-export.json",
        serde_json::to_string_pretty(&json).unwrap_or_default(),
    );
}

/// Simple timestamp without requiring chrono crate
fn chrono_now_fallback() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix:{}", secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report_json() -> &'static str {
        r#"{
            "summary": {
                "direct_deps": 5,
                "transitive_deps": 10,
                "total_flags": 2,
                "critical": 1,
                "high": 1,
                "medium": 0,
                "low": 0
            },
            "risk_flags": [
                {
                    "dependency": {
                        "org": "com.typesafe.play",
                        "name": "play-json",
                        "version": "2.3.2",
                        "scope": null,
                        "cross_compiled": true,
                        "source_file": "build.sbt",
                        "is_transitive": false
                    },
                    "severity": "Critical",
                    "reason": "Multiple RCE vulnerabilities",
                    "cve_ids": ["CVE-2019-17598"],
                    "risk_type": "KnownVulnerable",
                    "fix_suggestion": "Upgrade to >= 2.8.0"
                },
                {
                    "dependency": {
                        "org": "commons-net",
                        "name": "commons-net",
                        "version": "3.3",
                        "scope": "compile",
                        "cross_compiled": false,
                        "source_file": "build.sbt",
                        "is_transitive": false
                    },
                    "severity": "High",
                    "reason": "Known FTP vulnerability",
                    "cve_ids": ["CVE-2021-37533"],
                    "risk_type": "KnownVulnerable",
                    "fix_suggestion": "Upgrade to >= 3.9.0"
                }
            ],
            "code_references": {
                "com.typesafe.play:play-json": [
                    {
                        "dep_coord": "com.typesafe.play:play-json",
                        "file": "app/actors/StickerImageActor.scala",
                        "line_number": 16,
                        "line_content": "import play.api.libs.json._",
                        "import_path": "play.api.libs.json"
                    }
                ]
            },
            "graph": {},
            "usage_reports": []
        }"#
    }

    #[test]
    fn test_parse_report() {
        let json = sample_report_json();
        let report: JReport = serde_json::from_str(json).unwrap();
        assert_eq!(report.summary.critical, 1);
        assert_eq!(report.risk_flags.len(), 2);
    }

    #[test]
    fn test_build_tui_deps() {
        let json = sample_report_json();
        let report: JReport = serde_json::from_str(json).unwrap();
        let (deps, summary) = build_tui_deps(report);
        assert_eq!(deps.len(), 2);
        assert_eq!(summary.direct_deps, 5);
        // First dep should be Critical (sorted by severity desc)
        assert_eq!(deps[0].severity, Some(JSeverity::Critical));
    }

    #[test]
    fn test_filter_modes() {
        assert_eq!(FilterMode::All.next(), FilterMode::Critical);
        assert_eq!(FilterMode::Unused.next(), FilterMode::All);
    }

    #[test]
    fn test_sort_modes() {
        assert_eq!(SortMode::Severity.next(), SortMode::Name);
        assert_eq!(SortMode::Version.next(), SortMode::Severity);
    }

    #[test]
    fn test_shorten_path() {
        let long = "app/actors/images/StickerImageActor.scala";
        assert_eq!(
            shorten_path(long),
            ".../actors/images/StickerImageActor.scala"
        );
        let short = "build.sbt";
        assert_eq!(shorten_path(short), "build.sbt");
    }

    #[test]
    fn test_format_short_name() {
        assert_eq!(
            format_short_name("com.typesafe.play:play-json"),
            "play-json"
        );
        assert_eq!(format_short_name("standalone"), "standalone");
    }

    #[test]
    fn test_refilter() {
        let json = sample_report_json();
        let report: JReport = serde_json::from_str(json).unwrap();
        let (deps, summary) = build_tui_deps(report);
        let total = deps.len();

        let mut state = TuiState {
            deps,
            filtered_indices: (0..total).collect(),
            selected_index: 0,
            active_panel: Panel::Left,
            filter_mode: FilterMode::All,
            sort_mode: SortMode::Severity,
            search_query: String::new(),
            is_searching: false,
            list_state: ListState::default(),
            scroll_offset: 0,
            summary,
            status_message: None,
        };

        // All filter shows all
        state.refilter();
        assert_eq!(state.filtered_indices.len(), 2);

        // Critical filter
        state.filter_mode = FilterMode::Critical;
        state.refilter();
        assert_eq!(state.filtered_indices.len(), 1);

        // Search filter
        state.filter_mode = FilterMode::All;
        state.search_query = "play".to_string();
        state.refilter();
        assert_eq!(state.filtered_indices.len(), 1);
    }
}
