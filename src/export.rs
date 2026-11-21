//! Markdown export of the package versions and the vulnerability reports.
use crate::app::{App, ScanStatus};
use crate::vuln::{Source, Vuln};
use std::io::Write;
use std::process::{Command, Stdio};

fn cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

/// Today's local date as YYYY-MM-DD, from the system `date` command.
fn today() -> Option<String> {
    let out = Command::new("date").arg("+%Y-%m-%d").output().ok()?;
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (out.status.success() && !s.is_empty()).then_some(s)
}

pub fn markdown(app: &App) -> String {
    let mut out = format!("# {}: dependencies\n\n", app.project_name());
    if let Some(date) = today() {
        out.push_str(&format!("Date: {date}, "));
    }
    out.push_str(&format!(
        "package manager: {}, registry: {}\n\n",
        app.pm.name(),
        app.registry
    ));
    out.push_str("| Package | Type | Current | Latest | Status |\n|---|---|---|---|---|\n");
    for r in &app.rows {
        let mut status = (if r.outdated { "outdated" } else { "up to date" }).to_string();
        let snyk = r.vulns.iter().filter(|v| v.source == Source::Snyk).count();
        let audit = r.vulns.len() - snyk;
        if snyk > 0 {
            status.push_str(&format!(", snyk({snyk})"));
        }
        if audit > 0 {
            status.push_str(&format!(", audit({audit})"));
        }
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            cell(&r.name),
            r.kind.label(),
            r.current,
            r.latest,
            status
        ));
    }
    for (source, scan) in [(Source::Snyk, &app.snyk), (app.audit_source(), &app.audit)] {
        let ScanStatus::Done { .. } = scan.status else {
            continue;
        };
        let mut vulns: Vec<&Vuln> = app
            .rows
            .iter()
            .flat_map(|r| &r.vulns)
            .filter(|v| v.source == source)
            .collect();
        vulns.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.package.cmp(&b.package)));
        let name = if source == Source::Snyk { "Snyk" } else { source.label() };
        out.push_str(&format!("\n## {name} report\n\n"));
        if vulns.is_empty() {
            out.push_str("No known vulnerabilities.\n");
            continue;
        }
        out.push_str("| Severity | Package | Via | Issue | Fix |\n|---|---|---|---|---|\n");
        for v in vulns {
            let via = if v.path.is_empty() {
                "direct".to_string()
            } else {
                format!("{} > {}", v.direct, v.path.join(" > "))
            };
            let id = if v.cve.is_empty() {
                v.id.clone()
            } else {
                format!("{} ({})", v.id, v.cve.join(", "))
            };
            out.push_str(&format!(
                "| {} | {}@{} | {} | {}: {} | {} |\n",
                v.severity.label(),
                cell(&v.package),
                cell(&v.version),
                cell(&via),
                cell(&id),
                cell(&v.title),
                cell(&v.fix_summary())
            ));
        }
    }
    out
}

/// Copies text to the system clipboard with the platform's clipboard tool.
pub fn copy(text: &str) -> Result<(), String> {
    let candidates: &[(&str, &[&str])] = &[
        ("pbcopy", &[]),
        ("wl-copy", &[]),
        ("xclip", &["-selection", "clipboard"]),
        ("xsel", &["--clipboard", "--input"]),
        ("clip.exe", &[]),
    ];
    for (cmd, args) in candidates {
        let Ok(mut child) = Command::new(cmd)
            .args(*args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            continue;
        };
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(text.as_bytes());
        }
        return match child.wait() {
            Ok(s) if s.success() => Ok(()),
            _ => Err(format!("{cmd} failed")),
        };
    }
    Err("no clipboard tool found (pbcopy, wl-copy, xclip, xsel)".to_string())
}
