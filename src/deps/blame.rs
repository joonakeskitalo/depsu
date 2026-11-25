//! Who last changed a line of a file, and when, from `git blame`. Used to say who committed
//! the installed version of a package (lockfile), an override (`package.json`) or an ignore
//! rule (`.snyk`).
use std::collections::HashMap;
use std::ops::Range;
use std::path::Path;
use std::process::Command;

/// Where a line comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    /// The commit that last changed it: its author and the time it was authored (Unix seconds).
    Committed { author: String, time: i64 },
    /// The working tree changed it after the last commit.
    Uncommitted,
}

impl Origin {
    /// E.g. `committed by Jane Doe on 2026-03-02`.
    pub fn label(&self) -> String {
        match self {
            Origin::Committed { author, time } => {
                format!("committed by {author} on {}", crate::security::policy::date_of(*time))
            }
            Origin::Uncommitted => "not committed yet".to_string(),
        }
    }
}

/// A file as the working tree has it, with the origin of every line.
pub struct Blame {
    text: Vec<String>,
    /// Per line, an index into `origins`.
    owner: Vec<usize>,
    origins: Vec<Origin>,
}

impl Blame {
    /// Blames `file` (relative to `dir`). `None` outside a repository, or for a file git
    /// doesn't know.
    pub fn of(dir: &Path, file: &str) -> Option<Blame> {
        let out = Command::new("git")
            .args(["blame", "--porcelain", "--", file])
            .current_dir(dir)
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| Blame::parse(&String::from_utf8_lossy(&out.stdout)))
    }

    /// Reads the output of `git blame --porcelain`.
    pub fn parse(porcelain: &str) -> Blame {
        let mut blame = Blame { text: Vec::new(), owner: Vec::new(), origins: Vec::new() };
        let mut index: HashMap<String, usize> = HashMap::new();
        let (mut sha, mut author, mut time) = (String::new(), String::new(), 0i64);
        for line in porcelain.lines() {
            if let Some(content) = line.strip_prefix('\t') {
                // The author lines come with the first line of a commit only.
                let at = *index.entry(sha.clone()).or_insert_with(|| {
                    let origin = if sha.chars().all(|c| c == '0') {
                        Origin::Uncommitted
                    } else {
                        Origin::Committed { author: author.clone(), time }
                    };
                    blame.origins.push(origin);
                    blame.origins.len() - 1
                });
                blame.owner.push(at);
                blame.text.push(content.to_string());
            } else if let Some(a) = line.strip_prefix("author ") {
                author = a.to_string();
            } else if let Some(t) = line.strip_prefix("author-time ") {
                time = t.trim().parse().unwrap_or(0);
            } else {
                let mut words = line.split_whitespace();
                if let (Some(first), Some(_), Some(_)) = (words.next(), words.next(), words.next())
                    && matches!(first.len(), 40 | 64)
                    && first.chars().all(|c| c.is_ascii_hexdigit())
                {
                    sha = first.to_string();
                }
            }
        }
        blame
    }

    pub fn origin(&self, line: usize) -> Option<Origin> {
        self.owner.get(line).map(|&i| self.origins[i].clone())
    }

    /// The newest origin among `lines`; uncommitted when any of them is.
    pub fn newest(&self, lines: Range<usize>) -> Option<Origin> {
        let mut best: Option<Origin> = None;
        for i in lines {
            match (self.origin(i)?, &best) {
                (Origin::Uncommitted, _) => return Some(Origin::Uncommitted),
                (o @ Origin::Committed { .. }, None) => best = Some(o),
                (Origin::Committed { author, time }, Some(Origin::Committed { time: t, .. })) if time > *t => {
                    best = Some(Origin::Committed { author, time })
                }
                _ => {}
            }
        }
        best
    }

    fn indent(line: &str) -> usize {
        line.len() - line.trim_start().len()
    }

    /// The line of an entry of `package.json`, from the chain of keys down to it.
    pub fn json_key(&self, path: &[String]) -> Option<usize> {
        let root = self
            .text
            .iter()
            .filter(|l| l.trim_start().starts_with('"'))
            .map(|l| Blame::indent(l))
            .min()?;
        let mut parent: Option<(usize, usize)> = None; // line, indent
        for key in path {
            let needle = format!("{}:", serde_json::to_string(key).ok()?);
            let from = parent.map_or(0, |(i, _)| i + 1);
            let mut hit = None;
            for (i, l) in self.text.iter().enumerate().skip(from) {
                let (indent, t) = (Blame::indent(l), l.trim());
                match parent {
                    Some((_, p)) if !t.is_empty() && indent <= p => break,
                    Some(_) => {}
                    None if indent != root => continue,
                    None => {}
                }
                if t.starts_with(&needle) {
                    hit = Some((i, indent));
                    break;
                }
            }
            parent = Some(hit?);
        }
        parent.map(|(i, _)| i)
    }

    /// The lines of an ignore rule in `.snyk`: its path line and what is nested under it.
    pub fn policy_rule(&self, id: &str, path: &str) -> Option<Range<usize>> {
        // A line as `(indent, is a list item, key)`.
        let parse = |l: &str| {
            let t = l.trim();
            let (dash, t) = match t.strip_prefix("- ") {
                Some(r) => (true, r.trim_start()),
                None => (false, t),
            };
            let key = t.trim_end().strip_suffix(':')?.trim().trim_matches(['\'', '"']);
            Some((Blame::indent(l), dash, key.to_string()))
        };
        let ignore = self.text.iter().position(|l| l.trim_end() == "ignore:")?;
        let mut id_line = None;
        for (i, l) in self.text.iter().enumerate().skip(ignore + 1) {
            if !l.trim().is_empty() && Blame::indent(l) == 0 {
                break;
            }
            if let Some((indent, false, key)) = parse(l)
                && key == id
            {
                id_line = Some((i, indent));
                break;
            }
        }
        let (id_at, id_indent) = id_line?;
        for (i, l) in self.text.iter().enumerate().skip(id_at + 1) {
            let indent = Blame::indent(l);
            let item = parse(l);
            let dash = item.as_ref().is_some_and(|(_, d, _)| *d);
            if !l.trim().is_empty() && (indent < id_indent || (indent == id_indent && !dash)) {
                break;
            }
            if let Some((_, true, key)) = item
                && key == path
            {
                let end = self.text[i + 1..]
                    .iter()
                    .position(|n| !n.trim().is_empty() && Blame::indent(n) <= indent)
                    .map_or(self.text.len(), |n| i + 1 + n);
                return Some(i..end);
            }
        }
        None
    }

    /// The line of the version of `name` in npm's lockfile.
    pub fn npm_lock(&self, name: &str) -> Option<usize> {
        let head = format!("\"node_modules/{name}\": {{");
        let at = self.text.iter().position(|l| l.trim() == head)?;
        let indent = Blame::indent(&self.text[at]);
        let version = self.text[at + 1..]
            .iter()
            .take_while(|l| l.trim().is_empty() || Blame::indent(l) > indent)
            .position(|l| l.trim_start().starts_with("\"version\":"));
        Some(version.map_or(at, |n| at + 1 + n))
    }

    /// The line of `name@version` in pnpm's lockfile.
    pub fn pnpm_lock(&self, name: &str, version: &str) -> Option<usize> {
        let start = self.text.iter().position(|l| l.trim_end() == "packages:")?;
        let (at, rest) = (format!("{name}@{version}"), format!("{name}/{version}"));
        for (i, l) in self.text.iter().enumerate().skip(start + 1) {
            if !l.trim().is_empty() && Blame::indent(l) == 0 && !l.starts_with('#') {
                break;
            }
            if Blame::indent(l) != 2 {
                continue;
            }
            let key = l.trim().trim_end_matches(':').trim_matches(['\'', '"']).trim_start_matches('/');
            for want in [&at, &rest] {
                if key.strip_prefix(want.as_str()).is_some_and(|r| r.is_empty() || r.starts_with('(')) {
                    return Some(i);
                }
            }
        }
        None
    }
}
