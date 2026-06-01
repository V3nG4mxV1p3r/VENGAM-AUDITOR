// VENGAM — Rust Native Engine v2
// Sprint 10: parallel_scan + elf_deep eklendi

use pyo3::prelude::*;

mod elf_scanner;
mod il2cpp;
mod string_extractor;
mod entropy;
mod parallel_scan;
mod elf_deep;

#[pymodule]
fn phantom_native(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    // Sprint 3 — orijinal
    m.add_function(wrap_pyfunction!(string_extractor::extract_strings_py, m)?)?;
    m.add_function(wrap_pyfunction!(elf_scanner::scan_elf_py, m)?)?;
    m.add_function(wrap_pyfunction!(elf_scanner::get_elf_security_flags_py, m)?)?;
    m.add_function(wrap_pyfunction!(il2cpp::parse_il2cpp_metadata_py, m)?)?;
    m.add_function(wrap_pyfunction!(il2cpp::find_il2cpp_binary_py, m)?)?;
    m.add_function(wrap_pyfunction!(entropy::shannon_entropy_py, m)?)?;
    m.add_function(wrap_pyfunction!(entropy::scan_high_entropy_strings_py, m)?)?;

    // Sprint 10 — yeni
    m.add_function(wrap_pyfunction!(parallel_scan::parallel_scan_py, m)?)?;
    m.add_function(wrap_pyfunction!(parallel_scan::scan_stats_py, m)?)?;
    m.add_function(wrap_pyfunction!(elf_deep::analyze_elf_deep_py, m)?)?;

    Ok(())
}
