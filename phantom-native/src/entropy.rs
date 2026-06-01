// VENGAM — Fast Shannon Entropy Calculator
// Scans extracted strings for high-entropy candidates.

use pyo3::prelude::*;

pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let mut counts = [0u32; 256];
    for b in s.bytes() { counts[b as usize] += 1; }
    let len = s.len() as f64;
    counts.iter()
        .filter(|&&c| c > 0)
        .map(|&c| { let p = c as f64 / len; -p * p.log2() })
        .sum()
}

#[derive(Debug)]
pub struct HighEntropyString {
    pub value:   String,
    pub entropy: f64,
}

pub fn scan_high_entropy(
    strings: &[String],
    threshold: f64,
    min_len: usize,
) -> Vec<HighEntropyString> {
    strings.iter()
        .filter(|s| s.len() >= min_len)
        .filter_map(|s| {
            let e = shannon_entropy(s);
            if e >= threshold { Some(HighEntropyString { value: s.clone(), entropy: e }) }
            else { None }
        })
        .collect()
}

#[pyfunction]
#[pyo3(name = "shannon_entropy")]
pub fn shannon_entropy_py(s: &str) -> f64 {
    shannon_entropy(s)
}

/// Scan a list of strings and return those above the entropy threshold.
/// Returns list of (string, entropy) tuples.
#[pyfunction]
#[pyo3(name = "scan_high_entropy_strings")]
pub fn scan_high_entropy_strings_py(
    strings: Vec<String>,
    threshold: Option<f64>,
    min_len: Option<usize>,
) -> PyResult<Vec<(String, f64)>> {
    let threshold = threshold.unwrap_or(4.5);
    let min_len   = min_len.unwrap_or(12);
    Ok(scan_high_entropy(&strings, threshold, min_len)
        .into_iter()
        .map(|h| (h.value, h.entropy))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_string_entropy_zero() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn test_uniform_string_low_entropy() {
        assert!(shannon_entropy("aaaaaaaaaa") < 1.0);
    }

    #[test]
    fn test_high_entropy_api_key() {
        let key = "AIzaSyABCDEF1234567890abcdefghijk";
        assert!(shannon_entropy(key) > 4.0);
    }

    #[test]
    fn test_scan_filters_by_threshold() {
        let strings = vec![
            "aaaaaaaaaa".to_string(),
            "AIzaSyABCDEF1234567890abcdefghijk".to_string(),
        ];
        let results = scan_high_entropy(&strings, 4.0, 8);
        assert_eq!(results.len(), 1);
        assert!(results[0].value.starts_with("AIza"));
    }
}
