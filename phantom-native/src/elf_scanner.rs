// VENGAM — ELF / Shared Object Scanner
// Uses goblin crate to parse ELF headers, sections, and dynamic symbols.

use goblin::elf::Elf;
use pyo3::prelude::*;
use std::collections::HashMap;
use std::fs;

// ── ELF Security Flags ────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ElfSecurityFlags {
    pub pie:           bool,   // ET_DYN with EXEC intent → PIE
    pub nx:            bool,   // GNU_STACK non-executable
    pub relro:         bool,   // GNU_RELRO segment present
    pub bind_now:      bool,   // DF_BIND_NOW in dynamic flags
    pub canary:        bool,   // __stack_chk_fail imported
    pub fortify:       bool,   // __printf_chk / __memcpy_chk etc.
    pub stripped:      bool,   // No .symtab section
    pub rpath:         bool,   // DT_RPATH present (hijack risk)
    pub runpath:       bool,   // DT_RUNPATH present
    pub soname:        String, // Library name
}

impl Default for ElfSecurityFlags {
    fn default() -> Self {
        ElfSecurityFlags {
            pie: false, nx: false, relro: false, bind_now: false,
            canary: false, fortify: false, stripped: false,
            rpath: false, runpath: false, soname: String::new(),
        }
    }
}

pub fn analyse_elf(data: &[u8]) -> Option<ElfSecurityFlags> {
    let elf = Elf::parse(data).ok()?;
    let mut flags = ElfSecurityFlags::default();

    // PIE: ET_DYN type
    flags.pie = elf.header.e_type == goblin::elf::header::ET_DYN;

    // NX / non-executable stack
    for ph in &elf.program_headers {
        if ph.p_type == goblin::elf::program_header::PT_GNU_STACK {
            // If PF_X (execute) bit is NOT set → NX enabled
            flags.nx = (ph.p_flags & goblin::elf::program_header::PF_X) == 0;
        }
        if ph.p_type == goblin::elf::program_header::PT_GNU_RELRO {
            flags.relro = true;
        }
    }

    // Dynamic section flags
    for dyn_entry in &elf.dynamic.iter().flat_map(|d| d.dyns.iter()).collect::<Vec<_>>() {
        match dyn_entry.d_tag {
            goblin::elf::dynamic::DT_FLAGS => {
                if dyn_entry.d_val & goblin::elf::dynamic::DF_BIND_NOW != 0 {
                    flags.bind_now = true;
                }
            }
            goblin::elf::dynamic::DT_RPATH   => { flags.rpath    = true; }
            goblin::elf::dynamic::DT_RUNPATH => { flags.runpath  = true; }
            goblin::elf::dynamic::DT_SONAME  => {
                if let Some(name) = elf.dynstrtab.get_at(dyn_entry.d_val as usize) {
                    flags.soname = name.to_string();
                }
            }
            _ => {}
        }
    }

    // Imported symbols → canary + fortify
    for sym in elf.dynsyms.iter() {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if name.contains("__stack_chk_fail") || name.contains("__stack_chk_guard") {
                flags.canary = true;
            }
            if name.contains("_chk") || name.contains("__printf_chk") {
                flags.fortify = true;
            }
        }
    }

    // Stripped: no .symtab
    flags.stripped = !elf.section_headers.iter().any(|sh| {
        elf.shdr_strtab
            .get_at(sh.sh_name)
            .map(|n| n == ".symtab")
            .unwrap_or(false)
    });

    Some(flags)
}

// ── Exported symbols ──────────────────────────────────────────────────────────

pub fn get_exported_symbols(data: &[u8]) -> Vec<String> {
    let elf = match Elf::parse(data) {
        Ok(e) => e,
        Err(_) => return vec![],
    };

    elf.dynsyms
        .iter()
        .filter(|sym| sym.is_function() && sym.st_value != 0)
        .filter_map(|sym| elf.dynstrtab.get_at(sym.st_name))
        .map(|n| n.to_string())
        .collect()
}

// ── Interesting symbols for game security ────────────────────────────────────

const INTERESTING_SYMBOLS: &[(&str, &str, &str)] = &[
    // (fragment, title, severity)
    ("anti_cheat",       "Anti-Cheat Symbol",              "HIGH"),
    ("anticheat",        "Anti-Cheat Symbol",              "HIGH"),
    ("GameGuard",        "GameGuard Anti-Cheat",           "HIGH"),
    ("XignCode",         "XignCode Anti-Cheat",            "HIGH"),
    ("isRooted",         "Root Detection Symbol",          "MEDIUM"),
    ("jailbreak",        "Jailbreak Detection Symbol",     "MEDIUM"),
    ("bypass",           "Bypass Symbol",                  "CRITICAL"),
    ("cheat",            "Cheat-Related Symbol",           "HIGH"),
    ("god_mode",         "God Mode Symbol",                "HIGH"),
    ("godMode",          "God Mode Symbol",                "HIGH"),
    ("verify_purchase",  "IAP Verification Symbol",        "MEDIUM"),
    ("receipt_valid",    "Receipt Validation Symbol",      "MEDIUM"),
    ("decrypt_key",      "Decryption Key Symbol",          "CRITICAL"),
    ("aes_key",          "AES Key Symbol",                 "CRITICAL"),
    ("il2cpp",           "IL2CPP Runtime Symbol",          "INFO"),
    ("Unity",            "Unity Engine Symbol",            "INFO"),
    ("UE4",              "Unreal Engine Symbol",           "INFO"),
    ("pak_encrypt",      "PAK Encryption Symbol",          "CRITICAL"),
];

pub fn scan_interesting_symbols(data: &[u8]) -> Vec<HashMap<String, String>> {
    let symbols = get_exported_symbols(data);
    let mut findings: Vec<HashMap<String, String>> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for sym in &symbols {
        for &(fragment, title, severity) in INTERESTING_SYMBOLS {
            if sym.to_lowercase().contains(&fragment.to_lowercase()) {
                let key = format!("{}-{}", title, severity);
                if !seen.contains(&key) {
                    seen.insert(key);
                    let mut m = HashMap::new();
                    m.insert("title".into(),    title.into());
                    m.insert("severity".into(), severity.into());
                    m.insert("symbol".into(),   sym.clone());
                    findings.push(m);
                }
            }
        }
    }
    findings
}

// ── Linked libraries ──────────────────────────────────────────────────────────

pub fn get_linked_libraries(data: &[u8]) -> Vec<String> {
    let elf = match Elf::parse(data) {
        Ok(e) => e,
        Err(_) => return vec![],
    };

    elf.libraries.iter().map(|s| s.to_string()).collect()
}

// ── Python-callable wrappers ──────────────────────────────────────────────────

/// Full ELF security scan. Returns dict of findings + flags.
#[pyfunction]
#[pyo3(name = "scan_elf")]
pub fn scan_elf_py(path: &str) -> PyResult<PyObject> {
    let data = fs::read(path).map_err(|e| {
        pyo3::exceptions::PyIOError::new_err(format!("Cannot read {}: {}", path, e))
    })?;

    Python::with_gil(|py| {
        let result = pyo3::types::PyDict::new(py);

        // Security flags
        if let Some(flags) = analyse_elf(&data) {
            let flags_dict = pyo3::types::PyDict::new(py);
            flags_dict.set_item("pie",      flags.pie)?;
            flags_dict.set_item("nx",       flags.nx)?;
            flags_dict.set_item("relro",    flags.relro)?;
            flags_dict.set_item("bind_now", flags.bind_now)?;
            flags_dict.set_item("canary",   flags.canary)?;
            flags_dict.set_item("fortify",  flags.fortify)?;
            flags_dict.set_item("stripped", flags.stripped)?;
            flags_dict.set_item("rpath",    flags.rpath)?;
            flags_dict.set_item("runpath",  flags.runpath)?;
            flags_dict.set_item("soname",   flags.soname)?;
            result.set_item("security_flags", flags_dict)?;
        }

        // Interesting symbols
        let sym_findings = scan_interesting_symbols(&data);
        let sym_list     = pyo3::types::PyList::empty(py);
        for f in sym_findings {
            let d = pyo3::types::PyDict::new(py);
            for (k, v) in &f {
                d.set_item(k, v)?;
            }
            sym_list.append(d)?;
        }
        result.set_item("symbol_findings", sym_list)?;

        // Linked libraries
        let libs = get_linked_libraries(&data);
        result.set_item("linked_libs", libs)?;

        Ok(result.into())
    })
}

/// Returns only security flags as a Python dict.
#[pyfunction]
#[pyo3(name = "get_elf_security_flags")]
pub fn get_elf_security_flags_py(path: &str) -> PyResult<PyObject> {
    let data = fs::read(path).map_err(|e| {
        pyo3::exceptions::PyIOError::new_err(format!("Cannot read {}: {}", path, e))
    })?;

    Python::with_gil(|py| {
        let d = pyo3::types::PyDict::new(py);
        if let Some(flags) = analyse_elf(&data) {
            d.set_item("pie",      flags.pie)?;
            d.set_item("nx",       flags.nx)?;
            d.set_item("relro",    flags.relro)?;
            d.set_item("bind_now", flags.bind_now)?;
            d.set_item("canary",   flags.canary)?;
            d.set_item("fortify",  flags.fortify)?;
            d.set_item("stripped", flags.stripped)?;
            d.set_item("rpath",    flags.rpath)?;
            d.set_item("runpath",  flags.runpath)?;
            d.set_item("soname",   flags.soname)?;
        }
        Ok(d.into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_data_returns_none() {
        assert!(analyse_elf(b"").is_none());
    }

    #[test]
    fn test_invalid_elf_returns_none() {
        assert!(analyse_elf(b"not an elf file").is_none());
    }
}
