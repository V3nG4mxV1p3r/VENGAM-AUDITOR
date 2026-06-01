// VENGAM — Parallel Pattern Scanner
// Rayon ile çok çekirdekli pattern tarama.
// Python'dan 10-20x hızlı çalışır büyük APK'larda.

use rayon::prelude::*;
use pyo3::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use regex::Regex;

// ── Taranacak uzantılar ───────────────────────────────────────────
const SCANNABLE_EXTS: &[&str] = &[
    ".smali", ".xml", ".json", ".properties",
    ".gradle", ".kt", ".java", ".yaml", ".yml",
    ".config", ".env", ".ini", ".txt",
];

const IGNORE_FRAGMENTS: &[&str] = &[
    "EmojiCompat", "ComponentActivity", "BuildConfig",
    "R.smali", "Manifest.smali", "BR.smali",
];

// ── Pattern tanımı ────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct ScanPattern {
    pub id:          String,
    pub title:       String,
    pub regex:       String,
    pub severity:    String,
    pub score_value: u32,
    pub category:    String,
}

// ── Eşleşme sonucu ───────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct PatternMatch {
    pub pattern_id:   String,
    pub title:        String,
    pub severity:     String,
    pub score_value:  u32,
    pub category:     String,
    pub file_path:    String,
    pub line_number:  usize,
    pub matched_text: String,
    pub snippet:      String,
}

// ── Dosya tarayıcı ────────────────────────────────────────────────
fn should_scan(path: &Path) -> bool {
    let ext = path.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    let ext_with_dot = format!(".{}", ext);

    if !SCANNABLE_EXTS.contains(&ext_with_dot.as_str()) {
        return false;
    }
    let fname = path.file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("");
    !IGNORE_FRAGMENTS.iter().any(|frag| fname.contains(frag))
}

fn collect_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                files.extend(collect_files(&path));
            } else if path.is_file() && should_scan(&path) {
                files.push(path);
            }
        }
    }
    files
}

fn redact(s: &str) -> String {
    let len = s.len();
    if len <= 10 {
        return "***REDACTED***".to_string();
    }
    format!("{}{}{}",
        &s[..4],
        "*".repeat(len - 8),
        &s[len-4..]
    )
}

fn scan_file(
    path:     &Path,
    patterns: &[(ScanPattern, Regex)],
    base_dir: &Path,
) -> Vec<PatternMatch> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let relative = path.strip_prefix(base_dir)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string();

    let mut matches = Vec::new();

    for (line_no, line) in content.lines().enumerate() {
        for (pat, regex) in patterns {
            if let Some(m) = regex.find(line) {
                let matched = m.as_str();
                matches.push(PatternMatch {
                    pattern_id:   pat.id.clone(),
                    title:        pat.title.clone(),
                    severity:     pat.severity.clone(),
                    score_value:  pat.score_value,
                    category:     pat.category.clone(),
                    file_path:    relative.clone(),
                    line_number:  line_no + 1,
                    matched_text: redact(matched),
                    snippet:      line.trim().chars().take(120).collect(),
                });
                break; // Satır başına bir match yeterli
            }
        }
    }
    matches
}

// ── Ana parallel tarayıcı ─────────────────────────────────────────
pub fn parallel_scan(
    decompiled_dir: &str,
    patterns:       Vec<ScanPattern>,
) -> Vec<PatternMatch> {
    let base = Path::new(decompiled_dir);
    let files = collect_files(base);

    // Regex'leri bir kez compile et
    let compiled: Vec<(ScanPattern, Regex)> = patterns
        .into_iter()
        .filter_map(|p| {
            match Regex::new(&p.regex) {
                Ok(r)  => Some((p, r)),
                Err(e) => {
                    eprintln!("[VENGAM] Regex compile hatası '{}': {}", p.id, e);
                    None
                }
            }
        })
        .collect();

    // Parallel dosya tarama (Rayon)
    let all_matches: Vec<Vec<PatternMatch>> = files
        .par_iter()
        .map(|file| scan_file(file, &compiled, base))
        .collect();

    all_matches.into_iter().flatten().collect()
}

// ── Python binding ────────────────────────────────────────────────
#[pyfunction]
#[pyo3(name = "parallel_scan")]
pub fn parallel_scan_py(
    decompiled_dir: &str,
    patterns_raw:   Vec<(String, String, String, String, u32, String)>,
    // (id, title, regex, severity, score, category)
) -> PyResult<Vec<PyObject>> {
    let patterns: Vec<ScanPattern> = patterns_raw
        .into_iter()
        .map(|(id, title, regex, severity, score, category)| ScanPattern {
            id, title, regex, severity, score_value: score, category,
        })
        .collect();

    let matches = parallel_scan(decompiled_dir, patterns);

    Python::with_gil(|py| {
        let result: Vec<PyObject> = matches
            .into_iter()
            .map(|m| {
                let d = pyo3::types::PyDict::new(py);
                d.set_item("pattern_id",   &m.pattern_id).unwrap();
                d.set_item("title",        &m.title).unwrap();
                d.set_item("severity",     &m.severity).unwrap();
                d.set_item("score_value",  m.score_value).unwrap();
                d.set_item("category",     &m.category).unwrap();
                d.set_item("file_path",    &m.file_path).unwrap();
                d.set_item("line_number",  m.line_number).unwrap();
                d.set_item("matched_text", &m.matched_text).unwrap();
                d.set_item("snippet",      &m.snippet).unwrap();
                d.into()
            })
            .collect();
        Ok(result)
    })
}

// ── İstatistik fonksiyonu ─────────────────────────────────────────
#[pyfunction]
#[pyo3(name = "scan_stats")]
pub fn scan_stats_py(decompiled_dir: &str) -> PyResult<PyObject> {
    let base  = Path::new(decompiled_dir);
    let files = collect_files(base);
    let total_lines: usize = files.par_iter().map(|f| {
        fs::read_to_string(f)
            .map(|c| c.lines().count())
            .unwrap_or(0)
    }).sum();

    Python::with_gil(|py| {
        let d = pyo3::types::PyDict::new(py);
        d.set_item("files_found",  files.len()).unwrap();
        d.set_item("total_lines",  total_lines).unwrap();
        d.set_item("cpu_threads",  rayon::current_num_threads()).unwrap();
        Ok(d.into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_scan_smali() {
        assert!(should_scan(Path::new("test.smali")));
    }

    #[test]
    fn test_should_not_scan_png() {
        assert!(!should_scan(Path::new("icon.png")));
    }

    #[test]
    fn test_should_not_scan_buildconfig() {
        assert!(!should_scan(Path::new("BuildConfig.smali")));
    }

    #[test]
    fn test_redact_long() {
        let r = redact("AIzaSyABCDEF1234567890");
        assert!(r.starts_with("AIza"));
        assert!(r.contains("****"));
    }

    #[test]
    fn test_redact_short() {
        assert_eq!(redact("abc"), "***REDACTED***");
    }
}
