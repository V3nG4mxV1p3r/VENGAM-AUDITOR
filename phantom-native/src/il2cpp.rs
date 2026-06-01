// VENGAM — IL2CPP global-metadata.dat Parser
// Parses Unity IL2CPP metadata to extract type names, method names,
// string literals — all without executing any code.

use pyo3::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};

// ── IL2CPP Magic ──────────────────────────────────────────────────────────────

const IL2CPP_MAGIC: u32 = 0xFAB11BAF;

// ── Metadata Header ───────────────────────────────────────────────────────────

#[repr(C)]
struct Il2CppGlobalMetadataHeader {
    magic:                           u32,
    version:                         i32,
    string_literal_offset:           i32,
    string_literal_count:            i32,
    string_literal_data_offset:      i32,
    string_literal_data_count:       i32,
    string_offset:                   i32,
    string_count:                    i32,
    events_offset:                   i32,
    events_count:                    i32,
    properties_offset:               i32,
    properties_count:                i32,
    methods_offset:                  i32,
    methods_count:                   i32,
    parameter_default_values_offset: i32,
    parameter_default_values_count:  i32,
    field_default_values_offset:     i32,
    field_default_values_count:      i32,
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4).map(|b| {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    })
}

fn read_i32_le(data: &[u8], offset: usize) -> Option<i32> {
    data.get(offset..offset + 4).map(|b| {
        i32::from_le_bytes([b[0], b[1], b[2], b[3]])
    })
}

// ── Validation ────────────────────────────────────────────────────────────────

pub fn is_il2cpp_metadata(data: &[u8]) -> bool {
    read_u32_le(data, 0).map(|m| m == IL2CPP_MAGIC).unwrap_or(false)
}

pub fn get_metadata_version(data: &[u8]) -> Option<i32> {
    if !is_il2cpp_metadata(data) {
        return None;
    }
    read_i32_le(data, 4)
}

// ── String extraction from metadata ──────────────────────────────────────────

/// Extract all C-strings from the string table section.
pub fn extract_metadata_strings(data: &[u8]) -> Vec<String> {
    if !is_il2cpp_metadata(data) {
        return vec![];
    }

    let string_offset = match read_i32_le(data, 28) {
        Some(v) if v > 0 => v as usize,
        _ => return vec![],
    };
    let string_count = match read_i32_le(data, 32) {
        Some(v) if v > 0 => v as usize,
        _ => return vec![],
    };

    let end = (string_offset + string_count).min(data.len());
    if string_offset >= data.len() {
        return vec![];
    }

    let string_section = &data[string_offset..end];
    extract_cstrings(string_section, 4)
}

/// Extract string literals (hardcoded game strings).
pub fn extract_string_literals(data: &[u8]) -> Vec<String> {
    if !is_il2cpp_metadata(data) {
        return vec![];
    }

    let lit_data_offset = match read_i32_le(data, 20) {
        Some(v) if v > 0 => v as usize,
        _ => return vec![],
    };
    let lit_data_count = match read_i32_le(data, 24) {
        Some(v) if v > 0 => v as usize,
        _ => return vec![],
    };

    let end = (lit_data_offset + lit_data_count).min(data.len());
    if lit_data_offset >= data.len() {
        return vec![];
    }

    let lit_section = &data[lit_data_offset..end];
    extract_cstrings(lit_section, 6)
}

fn extract_cstrings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut results = Vec::new();
    let mut start   = 0usize;

    for (i, &byte) in data.iter().enumerate() {
        if byte == 0 {
            let len = i - start;
            if len >= min_len {
                if let Ok(s) = std::str::from_utf8(&data[start..i]) {
                    if s.chars().all(|c| c.is_ascii() && !c.is_ascii_control()) {
                        results.push(s.to_owned());
                    }
                }
            }
            start = i + 1;
        }
    }
    results
}

// ── Security-relevant metadata analysis ──────────────────────────────────────

#[derive(Debug)]
pub struct Il2CppAnalysisResult {
    pub version:          i32,
    pub string_count:     usize,
    pub literal_count:    usize,
    pub security_strings: Vec<SecurityString>,
}

#[derive(Debug)]
pub struct SecurityString {
    pub value:    String,
    pub category: String,
    pub severity: String,
}

const SECURITY_KEYWORDS: &[(&str, &str, &str)] = &[
    // (keyword_fragment, category, severity)
    ("api_key",          "Hardcoded Credential",    "CRITICAL"),
    ("apikey",           "Hardcoded Credential",    "CRITICAL"),
    ("secret_key",       "Hardcoded Credential",    "CRITICAL"),
    ("secretkey",        "Hardcoded Credential",    "CRITICAL"),
    ("password",         "Hardcoded Credential",    "HIGH"),
    ("passwd",           "Hardcoded Credential",    "HIGH"),
    ("access_token",     "Authentication Token",    "HIGH"),
    ("bearer",           "Authentication Token",    "HIGH"),
    ("AIza",             "Firebase API Key",        "CRITICAL"),
    ("AKIA",             "AWS Access Key",          "CRITICAL"),
    ("sk_live",          "Stripe Secret Key",       "CRITICAL"),
    ("god_mode",         "Debug Flag",              "HIGH"),
    ("godmode",          "Debug Flag",              "HIGH"),
    ("invincible",       "Debug Flag",              "HIGH"),
    ("no_clip",          "Debug Flag",              "HIGH"),
    ("bypass_anticheat", "Anti-Cheat Bypass",       "CRITICAL"),
    ("disable_cheat",    "Anti-Cheat Bypass",       "CRITICAL"),
    ("pak_key",          "Asset Encryption Key",    "CRITICAL"),
    ("encryption_key",   "Asset Encryption Key",    "CRITICAL"),
    ("cheat_engine",     "Cheat Tool Reference",    "HIGH"),
    ("playfab_secret",   "Backend Secret",          "CRITICAL"),
    ("nakama_key",       "Backend Secret",          "CRITICAL"),
];

pub fn analyse_metadata_security(data: &[u8]) -> Option<Il2CppAnalysisResult> {
    if !is_il2cpp_metadata(data) {
        return None;
    }

    let version       = get_metadata_version(data).unwrap_or(0);
    let all_strings   = extract_metadata_strings(data);
    let all_literals  = extract_string_literals(data);
    let string_count  = all_strings.len();
    let literal_count = all_literals.len();

    let mut security_strings: Vec<SecurityString> = Vec::new();

    for s in all_strings.iter().chain(all_literals.iter()) {
        let lower = s.to_lowercase();
        for &(kw, category, severity) in SECURITY_KEYWORDS {
            if lower.contains(kw) {
                // Avoid duplicates
                if !security_strings.iter().any(|e: &SecurityString| e.value == *s) {
                    security_strings.push(SecurityString {
                        value:    s.clone(),
                        category: category.to_string(),
                        severity: severity.to_string(),
                    });
                }
                break;
            }
        }
    }

    Some(Il2CppAnalysisResult {
        version,
        string_count,
        literal_count,
        security_strings,
    })
}

// ── Find IL2CPP files in decompiled APK ──────────────────────────────────────

pub fn find_il2cpp_files(search_dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();

    let targets = [
        "global-metadata.dat",
        "libil2cpp.so",
        "libil2cpp.dylib",
    ];

    if let Ok(walker) = fs::read_dir(search_dir) {
        for entry in walker.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if targets.iter().any(|t| name == *t) {
                        found.push(path);
                    }
                }
            }
            if path.is_dir() {
                found.extend(find_il2cpp_files(&path));
            }
        }
    }
    found
}

// ── Python-callable wrappers ──────────────────────────────────────────────────

/// Parse IL2CPP global-metadata.dat and return security findings.
#[pyfunction]
#[pyo3(name = "parse_il2cpp_metadata")]
pub fn parse_il2cpp_metadata_py(path: &str) -> PyResult<PyObject> {
    let data = fs::read(path).map_err(|e| {
        pyo3::exceptions::PyIOError::new_err(format!("Cannot read {}: {}", path, e))
    })?;

    Python::with_gil(|py| {
        let result = pyo3::types::PyDict::new(py);

        if !is_il2cpp_metadata(&data) {
            result.set_item("valid", false)?;
            return Ok(result.into());
        }

        result.set_item("valid", true)?;

        match analyse_metadata_security(&data) {
            Some(analysis) => {
                result.set_item("version",       analysis.version)?;
                result.set_item("string_count",  analysis.string_count)?;
                result.set_item("literal_count", analysis.literal_count)?;

                let findings = pyo3::types::PyList::empty(py);
                for ss in &analysis.security_strings {
                    let d = pyo3::types::PyDict::new(py);
                    d.set_item("value",    &ss.value)?;
                    d.set_item("category", &ss.category)?;
                    d.set_item("severity", &ss.severity)?;
                    findings.append(d)?;
                }
                result.set_item("security_findings", findings)?;
            }
            None => {
                result.set_item("error", "Metadata analysis failed")?;
            }
        }

        Ok(result.into())
    })
}

/// Find IL2CPP related files in a directory tree.
#[pyfunction]
#[pyo3(name = "find_il2cpp_binary")]
pub fn find_il2cpp_binary_py(search_dir: &str) -> PyResult<Vec<String>> {
    let paths = find_il2cpp_files(Path::new(search_dir));
    Ok(paths
        .iter()
        .filter_map(|p| p.to_str().map(|s| s.to_string()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_magic_not_il2cpp() {
        assert!(!is_il2cpp_metadata(b"\x00\x00\x00\x00version"));
    }

    #[test]
    fn test_empty_not_il2cpp() {
        assert!(!is_il2cpp_metadata(b""));
    }

    #[test]
    fn test_valid_magic() {
        let mut data = vec![0u8; 64];
        let magic = IL2CPP_MAGIC.to_le_bytes();
        data[0] = magic[0];
        data[1] = magic[1];
        data[2] = magic[2];
        data[3] = magic[3];
        assert!(is_il2cpp_metadata(&data));
    }

    #[test]
    fn test_extract_cstrings_basic() {
        let data = b"hello\x00world\x00ab\x00verylongstring\x00";
        let strings = extract_cstrings(data, 5);
        assert!(strings.contains(&"hello".to_string()));
        assert!(strings.contains(&"world".to_string()));
        assert!(strings.contains(&"verylongstring".to_string()));
        assert!(!strings.contains(&"ab".to_string())); // too short
    }
}
