//! Find filter-list rules that have to do with a set of domains and report which ones
//! adblock-rust supports.
//!
//! A rule is "supported" only if adblock-rust both parses it and, when it depends on
//! a scriptlet or redirect resource, can resolve that resource. Otherwise it is
//! "unsupported" with a single reason (a parse error, or a missing/restricted resource).
//!
//! Run `adblock-rust-compat --help` for usage. A filter list (`--url`/`--file`)
//! is required; `--domains` is optional (omit to check every rule in the list).

mod domains;
mod resources;

use std::io::Read;

use adblock::lists::{
    parse_filter, FilterFormat, FilterParseError, ParseOptions, ParsedFilter, RuleTypes,
};
use adblock::resources::PermissionMask;

use domains::{DomainMatcher, Relation};
use resources::{ResourceChecker, ResourceStatus};

/// adblock-rust version this tool is built against (keep in sync with Cargo.toml).
const ADBLOCK_RUST_VERSION: &str = "0.12.x";

const UBO_URL: &str =
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt";
const EASYLIST_URL: &str = "https://easylist.to/easylist/easylist.txt";
const EASYPRIVACY_URL: &str = "https://easylist.to/easylist/easyprivacy.txt";

/// Resolve a `--list` value (a preset name or an http(s) URL) to a URL.
fn resolve_list(value: &str) -> Result<String, String> {
    match value {
        "ubo" => Ok(UBO_URL.to_string()),
        "easylist" => Ok(EASYLIST_URL.to_string()),
        "easyprivacy" => Ok(EASYPRIVACY_URL.to_string()),
        v if v.starts_with("http://") || v.starts_with("https://") => Ok(v.to_string()),
        other => Err(format!(
            "unknown list '{other}': use ubo, easylist, easyprivacy, or an http(s) URL"
        )),
    }
}

/// Expand `--list` values (comma-separated and/or repeated) into individual tokens,
/// trimmed, with empties dropped.
fn list_tokens(values: &[String]) -> Vec<String> {
    values
        .iter()
        .flat_map(|v| v.split(','))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[derive(serde::Serialize)]
struct RuleReport {
    rule: String,
    relations: Vec<Relation>,
    supported: bool,
    filter_type: Option<&'static str>,
    reason: Option<String>,
}

/// Top-level `--json` output: provenance (so downstream consumers don't have to restate
/// the adblock-rust version) plus the per-rule reports. Field order is stable for
/// deterministic, diff-friendly output.
#[derive(serde::Serialize)]
struct Report<'a> {
    adblock_version: &'static str,
    tool: &'static str,
    tool_version: &'static str,
    source: String,
    domains: Option<Vec<String>>,
    rules: &'a [RuleReport],
}

fn parse_options() -> ParseOptions {
    ParseOptions {
        rule_types: RuleTypes::All,
        format: FilterFormat::Standard,
        permissions: PermissionMask::from_bits(0),
    }
}

fn parse(rule: &str) -> (Option<ParsedFilter>, Option<&'static str>, Option<String>) {
    match parse_filter(rule, true, parse_options()) {
        Ok(p @ ParsedFilter::Network(_)) => (Some(p), Some("network"), None),
        Ok(p @ ParsedFilter::Cosmetic(_)) => (Some(p), Some("cosmetic"), None),
        Err(FilterParseError::Network(e)) => (None, Some("network"), Some(format!("{e:?}"))),
        Err(FilterParseError::Cosmetic(e)) => (None, Some("cosmetic"), Some(format!("{e:?}"))),
        Err(FilterParseError::Unsupported) => (None, None, Some("unsupported".into())),
        Err(FilterParseError::Empty) => (None, None, Some("empty".into())),
    }
}

fn support(
    rule: &str,
    parsed: &Option<ParsedFilter>,
    parse_error: Option<String>,
    resources: &ResourceChecker,
) -> (bool, Option<String>) {
    let Some(parsed) = parsed else {
        return (false, parse_error);
    };
    match resources.check_rule(parsed, rule) {
        ResourceStatus::NotApplicable | ResourceStatus::Ok => (true, None),
        ResourceStatus::Missing => (false, Some("resource missing".into())),
        ResourceStatus::RequiresPermission => (false, Some("resource requires permission".into())),
    }
}

fn is_filter_line(line: &str) -> bool {
    !line.is_empty() && !line.starts_with('!') && !line.starts_with('[')
}

fn fetch_list(url: &str) -> Result<String, String> {
    // Cap the response so a hostile or runaway URL can't exhaust memory, and time out
    // so it can't hang the run.
    const MAX_BYTES: u64 = 64 * 1024 * 1024;
    let resp = ureq::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .get(url)
        .call()
        .map_err(|e| format!("fetch failed: {e}"))?;
    let mut body = String::new();
    resp.into_reader()
        .take(MAX_BYTES)
        .read_to_string(&mut body)
        .map_err(|e| format!("read failed: {e}"))?;
    Ok(body)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_usage();
        return;
    }
    let output_json = args.iter().any(|a| a == "--json");
    let output_markdown = args.iter().any(|a| a == "--markdown");
    let show_supported = args.iter().any(|a| a == "--show-supported");
    let value_of = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1).cloned())
    };
    // All values passed to a repeatable flag (the arg following each occurrence).
    let values_of = |flag: &str| -> Vec<String> {
        args.iter()
            .enumerate()
            .filter(|(_, a)| a.as_str() == flag)
            .filter_map(|(i, _)| args.get(i + 1).cloned())
            .collect()
    };

    // Sources can be combined: any mix of --file, --list (preset/URL; comma-separated
    // and/or repeated), and --url (repeatable). Their rules are merged into one corpus
    // (duplicates across lists are de-duplicated below).
    let mut source_labels: Vec<String> = Vec::new();
    let mut texts: Vec<String> = Vec::new();

    for path in values_of("--file") {
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| fatal(&format!("could not read {path}: {e}")));
        source_labels.push(format!("file {path}"));
        texts.push(text);
    }
    for token in list_tokens(&values_of("--list")) {
        let url = resolve_list(&token).unwrap_or_else(|e| fatal(&e));
        eprintln!("Fetching {url} ...");
        texts.push(fetch_list(&url).unwrap_or_else(|e| fatal(&e)));
        source_labels.push(url);
    }
    for url in values_of("--url") {
        eprintln!("Fetching {url} ...");
        texts.push(fetch_list(&url).unwrap_or_else(|e| fatal(&e)));
        source_labels.push(url);
    }

    if source_labels.is_empty() {
        fatal("a filter list is required: --list <ubo|easylist|easyprivacy|URL ...>, --url URL, or --file PATH");
    }

    let source_label = source_labels.join(", ");
    let text = texts.join("\n");

    // No --domains means "check every rule" (no domain filtering).
    let domains: Option<Vec<String>> = match value_of("--domains") {
        Some(list) => {
            let v: Vec<String> = list
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if v.is_empty() {
                fatal("--domains was empty");
            }
            Some(v)
        }
        None => None,
    };
    match &domains {
        Some(d) => eprintln!("Matching domains: {}", d.join(", ")),
        None => eprintln!("No --domains given: checking all rules."),
    }
    let matcher = domains.as_ref().map(|d| DomainMatcher::new(d));
    let resource_checker = ResourceChecker::from_embedded();
    let mut reports: Vec<RuleReport> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in text.lines() {
        let rule = line.trim();
        if !is_filter_line(rule) || !seen.insert(rule.to_string()) {
            continue;
        }

        let (parsed, filter_type, parse_error) = parse(rule);

        // With a domain set, keep only related rules; without, keep everything.
        let relations = match &matcher {
            Some(m) => {
                let rels = match &parsed {
                    Some(p) => m.relations_parsed(p),
                    None => m.relations_raw(rule),
                };
                if rels.is_empty() {
                    continue;
                }
                rels
            }
            None => Vec::new(),
        };

        let (supported, reason) = support(rule, &parsed, parse_error, &resource_checker);

        reports.push(RuleReport {
            rule: rule.to_string(),
            relations,
            supported,
            filter_type,
            reason,
        });
    }

    if output_json {
        let report = Report {
            adblock_version: ADBLOCK_RUST_VERSION,
            tool: env!("CARGO_PKG_NAME"),
            tool_version: env!("CARGO_PKG_VERSION"),
            source: source_label.clone(),
            domains: domains.clone(),
            rules: &reports,
        };
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return;
    }

    if output_markdown {
        print_markdown(&reports, domains.as_deref(), &source_label);
        return;
    }

    print_report(&reports, show_supported, domains.is_some());
}

fn print_report(reports: &[RuleReport], show_supported: bool, domain_filtered: bool) {
    let supported = reports.iter().filter(|r| r.supported).count();
    let unsupported = reports.len() - supported;

    if domain_filtered {
        let targets = reports
            .iter()
            .filter(|r| r.relations.contains(&Relation::Target))
            .count();
        let scopes = reports
            .iter()
            .filter(|r| r.relations.contains(&Relation::Scope))
            .count();
        println!(
            "Matching rules: {}  (target: {targets}, scope: {scopes})",
            reports.len()
        );
    } else {
        println!("Rules checked:  {}", reports.len());
    }
    println!("Supported:      {supported}");
    println!("Unsupported:    {unsupported}");

    let mut unsupported_rules: Vec<&RuleReport> = reports.iter().filter(|r| !r.supported).collect();
    unsupported_rules
        .sort_by(|a, b| (a.reason.as_deref(), &a.rule).cmp(&(b.reason.as_deref(), &b.rule)));
    if !unsupported_rules.is_empty() {
        println!("\n=== UNSUPPORTED RULES ===");
        for r in unsupported_rules {
            println!(
                "{}({}) {}",
                tag_prefix(r),
                r.reason.as_deref().unwrap_or("?"),
                r.rule
            );
        }
    }

    if show_supported {
        println!("\n=== SUPPORTED RULES ===");
        for r in reports.iter().filter(|r| r.supported) {
            println!(
                "{}[{}] {}",
                tag_prefix(r),
                r.filter_type.unwrap_or("?"),
                r.rule
            );
        }
    }
}

fn tags(r: &RuleReport) -> String {
    r.relations
        .iter()
        .map(|rel| match rel {
            Relation::Target => "target",
            Relation::Scope => "scope",
        })
        .collect::<Vec<_>>()
        .join("+")
}

/// A `[tag+tag] ` prefix, or empty when the rule has no domain relations (match-all mode).
fn tag_prefix(r: &RuleReport) -> String {
    if r.relations.is_empty() {
        String::new()
    } else {
        format!("[{}] ", tags(r))
    }
}

/// Render a deterministic markdown report. Output depends only on the inputs (rules,
/// domains, source) so re-running on the same data yields identical bytes - safe to
/// commit and diff.
fn print_markdown(reports: &[RuleReport], domains: Option<&[String]>, source: &str) {
    let supported = reports.iter().filter(|r| r.supported).count();
    let unsupported = reports.len() - supported;
    let domain_filtered = domains.is_some();

    println!("# adblock-rust filter compatibility\n");

    println!("| | |");
    println!("|---|---|");
    println!("| Source | {} |", md_text(source));
    let domains_label = match domains {
        Some(d) => d.join(", "),
        None => "all (no domain filter)".to_string(),
    };
    println!("| Domains | {} |", md_text(&domains_label));
    println!("| adblock-rust | {ADBLOCK_RUST_VERSION} |");
    println!(
        "| Tool | {} v{} |",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    );
    println!();

    if domain_filtered {
        let targets = reports
            .iter()
            .filter(|r| r.relations.contains(&Relation::Target))
            .count();
        let scopes = reports
            .iter()
            .filter(|r| r.relations.contains(&Relation::Scope))
            .count();
        println!(
            "**{} matching rules** - {supported} supported, {unsupported} unsupported \
             (target: {targets}, scope: {scopes}).\n",
            reports.len()
        );
    } else {
        println!(
            "**{} rules checked** - {supported} supported, {unsupported} unsupported.\n",
            reports.len()
        );
    }

    let mut unsupported_rules: Vec<&RuleReport> = reports.iter().filter(|r| !r.supported).collect();
    unsupported_rules
        .sort_by(|a, b| (a.reason.as_deref(), &a.rule).cmp(&(b.reason.as_deref(), &b.rule)));
    println!("## Unsupported ({unsupported})\n");
    if unsupported_rules.is_empty() {
        println!("_None._\n");
    } else {
        let headers: &[&str] = if domain_filtered {
            &["Tags", "Reason", "Rule"]
        } else {
            &["Reason", "Rule"]
        };
        let rows: Vec<Vec<String>> = unsupported_rules
            .iter()
            .map(|r| {
                let mut row = Vec::new();
                if domain_filtered {
                    row.push(tags(r));
                }
                row.push(md_text(r.reason.as_deref().unwrap_or("?")));
                row.push(md_code(&r.rule));
                row
            })
            .collect();
        print_table(headers, &rows);
        println!();
    }

    let mut supported_rules: Vec<&RuleReport> = reports.iter().filter(|r| r.supported).collect();
    supported_rules.sort_by(|a, b| (a.filter_type, &a.rule).cmp(&(b.filter_type, &b.rule)));
    println!("## Supported ({supported})\n");
    if supported_rules.is_empty() {
        println!("_None._");
    } else {
        let headers: &[&str] = if domain_filtered {
            &["Tags", "Type", "Rule"]
        } else {
            &["Type", "Rule"]
        };
        let rows: Vec<Vec<String>> = supported_rules
            .iter()
            .map(|r| {
                let mut row = Vec::new();
                if domain_filtered {
                    row.push(tags(r));
                }
                row.push(r.filter_type.unwrap_or("?").to_string());
                row.push(md_code(&r.rule));
                row
            })
            .collect();
        print_table(headers, &rows);
    }
}

fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    println!("| {} |", headers.join(" | "));
    println!("|{}|", vec!["---"; headers.len()].join("|"));
    for row in rows {
        println!("| {} |", row.join(" | "));
    }
}

fn md_text(s: &str) -> String {
    s.replace('|', "\\|")
}

fn md_code(s: &str) -> String {
    format!("`{}`", s.replace('|', "\\|"))
}

fn print_usage() {
    println!(
        "{name} v{version} - check which filter-list rules adblock-rust supports

USAGE:
    adblock-rust-compat <SOURCE>... [--domains LIST] [OPTIONS]

SOURCE (one or more; their rules are combined and de-duplicated):
    --list NAMES|URLS    ubo, easylist, easyprivacy, or http(s) URLs; comma-separated
                         and/or repeated (e.g. --list ubo,easylist)
    --url URL            Raw URL (repeatable)
    --file PATH          Local file (repeatable)

OPTIONS:
    --domains LIST       Comma-separated domains to match (e.g. youtube.com,youtu.be);
                         omit to check every rule in the list
    --markdown           Emit a markdown report to stdout
    --json               Emit the full report as JSON to stdout
    --show-supported     Also list supported rules (text output only)
    -h, --help           Show this help

When --domains is given, list registrable domains (e.g. example.com) for broad subdomain
coverage, plus any specific subdomains used in cosmetic/$domain= scopes.
See examples/check-youtube.sh for the YouTube domain set.",
        name = env!("CARGO_PKG_NAME"),
        version = env!("CARGO_PKG_VERSION"),
    );
}

fn fatal(msg: &str) -> ! {
    eprintln!("Error: {msg}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_list_presets_and_urls() {
        assert_eq!(resolve_list("ubo").unwrap(), UBO_URL);
        assert_eq!(resolve_list("easylist").unwrap(), EASYLIST_URL);
        assert_eq!(resolve_list("easyprivacy").unwrap(), EASYPRIVACY_URL);
        assert_eq!(
            resolve_list("https://example.com/list.txt").unwrap(),
            "https://example.com/list.txt"
        );
        assert!(resolve_list("nonsense").is_err());
        // A stray flag captured as a value (e.g. `--list --json`) is rejected.
        assert!(resolve_list("--json").is_err());
    }

    #[test]
    fn list_tokens_split_and_repeat() {
        // comma-separated, repeated, and a mix all expand to individual tokens
        assert_eq!(
            list_tokens(&["ubo,easylist".to_string()]),
            vec!["ubo", "easylist"]
        );
        assert_eq!(
            list_tokens(&["ubo".to_string(), "easylist".to_string()]),
            vec!["ubo", "easylist"]
        );
        assert_eq!(
            list_tokens(&[" ubo , easyprivacy ".to_string(), "easylist".to_string()]),
            vec!["ubo", "easyprivacy", "easylist"]
        );
        // empties and stray commas are dropped
        assert_eq!(list_tokens(&["ubo,,".to_string()]), vec!["ubo"]);
        assert!(list_tokens(&[]).is_empty());
    }

    #[test]
    fn supported_network_rule() {
        let (parsed, ty, err) = parse("||ads.youtube.com^");
        assert!(parsed.is_some());
        assert_eq!(ty, Some("network"));
        assert!(err.is_none());
    }

    #[test]
    fn supported_cosmetic_rule() {
        let (parsed, ty, err) = parse("youtube.com##.ytp-ad-module");
        assert!(parsed.is_some());
        assert_eq!(ty, Some("cosmetic"));
        assert!(err.is_none());
    }

    #[test]
    fn rejected_replace_rule_reports_reason() {
        let rule = r#"||www.youtube.com/watch?$xhr,1p,replace=/"adPlacements"/"no_ads"/"#;
        let (parsed, ty, err) = parse(rule);
        assert!(parsed.is_none());
        assert_eq!(ty, Some("network"));
        assert!(
            err.as_deref().unwrap_or("").contains("Unrecognised"),
            "expected an UnrecognisedOption error, got {err:?}"
        );
    }

    #[test]
    fn unsupported_when_scriptlet_resource_missing() {
        let resources = ResourceChecker::from_embedded();
        let rule = "youtube.com##+js(this-scriptlet-does-not-exist-xyz)";
        let (parsed, _ty, parse_error) = parse(rule);
        assert!(parsed.is_some(), "rule should parse");
        let (supported, reason) = support(rule, &parsed, parse_error, &resources);
        assert!(!supported);
        assert_eq!(reason.as_deref(), Some("resource missing"));
    }

    #[test]
    fn supported_when_parses_and_resource_resolves() {
        let resources = ResourceChecker::from_embedded();
        let rule = "youtube.com##+js(set, foo, 1)";
        let (parsed, _ty, parse_error) = parse(rule);
        let (supported, reason) = support(rule, &parsed, parse_error, &resources);
        assert!(supported);
        assert!(reason.is_none());
    }

    #[test]
    fn comment_and_header_lines_are_not_filters() {
        assert!(!is_filter_line("! a comment"));
        assert!(!is_filter_line("[Adblock Plus 2.0]"));
        assert!(!is_filter_line(""));
        assert!(is_filter_line("||youtube.com^"));
    }
}
