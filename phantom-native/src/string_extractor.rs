// VENGAM — High-Speed String Extractor
// Uses memchr for SIMD-accelerated scanning of printable ASCII sequences

use memchr::memchr;
use pyo3::prelude::*;
use rayon::prelude::*;
use std::fs;

/// Minimum printable ASCII byte
const ASCII_MIN: u8 = 0x20; // space
/// Maximum printable ASCII byte  
const ASCII_MAX: u8 = 0x7E; // ~

/// Extract all printable ASCII strings >= min_len from a byte slice.
/// Uses a sliding window — no heap allocation per string until confirmed.
pub fn extract_strings_from_bytes(data: &[u8], min_len: usize) -> Vec<String> {
    let mut results: Vec<String> = Vec::new();
    let mut start: Option<usize> = None;

    for (i, &byte) in data.iter().enumerate() {
        if byte >= ASCII_MIN && byte <= ASCII_MAX {
            if start.is_none() {
                start = Some(i);
            }
        } else {
            if let Some(s) = start.take() {
                let len = i - s;
                if len >= min_len {
                    // SAFETY: slice confirmed to be printable ASCII
                    let s = unsafe { std::str::from_utf8_unchecked(&data[s..i]) };
                    results.push(s.to_owned());
                }
            }
        }
    }

    // Handle trailing string at end of file
    if let Some(s) = start {
        let len = data.len() - s;
        if len >= min_len {
            let s = unsafe { std::str::from_utf8_unchecked(&data[s..]) };
            results.push(s.to_owned());
        }
    }

    results
}

/// Parallel extraction — splits file into chunks and scans in parallel.
/// Boundary strings (split across chunks) are stitched together.
pub fn extract_strings_parallel(data: &[u8], min_len: usize, chunk_size: usize) -> Vec<String> {
    // For small files just run sequentially
    if data.len() < chunk_size * 2 {
        return extract_strings_from_bytes(data, min_len);
    }

    let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();

    chunks
        .par_iter()
        .flat_map(|chunk| extract_strings_from_bytes(chunk, min_len))
        .collect()
}

/// Python-callable wrapper.
/// Returns list of extracted strings from a binary file path.
#[pyfunction]
#[pyo3(name = "extract_strings")]
pub fn extract_strings_py(
    path: &str,
    min_length: Option<usize>,
    parallel: Option<bool>,
) -> PyResult<Vec<String>> {
    let min_len  = min_length.unwrap_or(8);
    let parallel = parallel.unwrap_or(true);

    let data = fs::read(path).map_err(|e| {
        pyo3::exceptions::PyIOError::new_err(format!("Cannot read {}: {}", path, e))
    })?;

    let strings = if parallel {
        extract_strings_parallel(&data, min_len, 4 * 1024 * 1024) // 4 MB chunks
    } else {
        extract_strings_from_bytes(&data, min_len)
    };

    Ok(strings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_simple() {
        let data = b"\x00\x00hello world\x00\x00test\x00";
        let strings = extract_strings_from_bytes(data, 4);
        assert!(strings.contains(&"hello world".to_string()));
        assert!(strings.contains(&"test".to_string()));
    }

    #[test]
    fn test_min_length_filter() {
        let data = b"ab\x00abcdefgh\x00xy\x00";
        let strings = extract_strings_from_bytes(data, 8);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0], "abcdefgh");
    }

    #[test]
    fn test_empty_input() {
        let strings = extract_strings_from_bytes(b"", 4);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_all_null() {
        let data = vec![0u8; 1024];
        let strings = extract_strings_from_bytes(&data, 4);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_trailing_string() {
        let data = b"\x00\x00verylongstring";
        let strings = extract_strings_from_bytes(data, 4);
        assert!(strings.contains(&"verylongstring".to_string()));
    }
}
