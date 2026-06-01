// VENGAM — Deep ELF/JNI Analyzer
// .so dosyalarında JNI method mapping, import/export analizi
// ve güvenlik zafiyeti tespiti yapar.

use goblin::elf::Elf;
use pyo3::prelude::*;
use std::collections::HashMap;
use std::fs;

// ── JNI method tespiti ────────────────────────────────────────────
// JNI metodları Java_PackageName_ClassName_methodName formatında
const JNI_PREFIX: &str = "Java_";

// Güvenlik açısından kritik import'lar
const DANGEROUS_IMPORTS: &[(&str, &str, &str)] = &[
    ("dlopen",          "Dynamic Loading",   "HIGH"),
    ("dlsym",           "Dynamic Loading",   "HIGH"),
    ("mprotect",        "Memory Protect",    "CRITICAL"),
    ("mmap",            "Memory Mapping",    "HIGH"),
    ("ptrace",          "Debug/Anti-Debug",  "CRITICAL"),
    ("fork",            "Process Fork",      "MEDIUM"),
    ("system",          "Shell Exec",        "CRITICAL"),
    ("execve",          "Shell Exec",        "CRITICAL"),
    ("__system_property_get", "Prop Read",  "MEDIUM"),
    ("fopen",           "File Access",       "LOW"),
    ("connect",         "Network",           "MEDIUM"),
    ("socket",          "Network",           "MEDIUM"),
    ("AES_encrypt",     "Crypto",            "HIGH"),
    ("AES_decrypt",     "Crypto",            "HIGH"),
    ("EVP_EncryptInit", "Crypto",            "HIGH"),
    ("RAND_bytes",      "Crypto RNG",        "MEDIUM"),
    ("anti_debug",      "Anti-Debug",        "CRITICAL"),
    ("detect_frida",    "Frida Detection",   "CRITICAL"),
    ("check_root",      "Root Detection",    "HIGH"),
];

// ── Veri yapıları ─────────────────────────────────────────────────

#[derive(Debug)]
pub struct JniMethod {
    pub symbol:      String,
    pub java_class:  String,
    pub java_method: String,
    pub address:     u64,
}

#[derive(Debug)]
pub struct DangerousImport {
    pub symbol:      String,
    pub category:    String,
    pub severity:    String,
    pub description: String,
}

#[derive(Debug)]
pub struct ElfDeepResult {
    pub soname:           String,
    pub arch:             String,
    pub jni_methods:      Vec<JniMethod>,
    pub dangerous_imports:Vec<DangerousImport>,
    pub exported_symbols: Vec<String>,
    pub linked_libs:      Vec<String>,
    pub security_flags: HashMap<String, bool>,
    pub string_hints:     Vec<String>,
}

// ── JNI parser ────────────────────────────────────────────────────

fn parse_jni_symbol(sym: &str) -> Option<JniMethod> {
    if !sym.starts_with(JNI_PREFIX) {
        return None;
    }
    let rest   = &sym[JNI_PREFIX.len()..];
    let parts:  Vec<&str> = rest.split('_').collect();
    if parts.len() < 2 {
        return None;
    }
    // Son parça method adı, geri kalanlar class path
    let method     = parts.last().unwrap().to_string();
    let class_path = parts[..parts.len()-1].join(".");
    Some(JniMethod {
        symbol:      sym.to_string(),
        java_class:  class_path,
        java_method: method,
        address:     0,
    })
}

// ── Arch tespiti ──────────────────────────────────────────────────
fn detect_arch(elf: &Elf) -> String {
    match elf.header.e_machine {
        0x28  => "ARM (32-bit)".to_string(),
        0xB7  => "ARM64 (64-bit)".to_string(),
        0x03  => "x86 (32-bit)".to_string(),
        0x3E  => "x86_64 (64-bit)".to_string(),
        other => format!("Unknown (0x{:X})", other),
    }
}

// ── Ana analiz fonksiyonu ─────────────────────────────────────────
pub fn analyze_elf_deep(data: &[u8]) -> Option<ElfDeepResult> {
    let elf = Elf::parse(data).ok()?;

    let arch   = detect_arch(&elf);
    let soname = elf.dynamic.as_ref()
        .and_then(|d| {
            d.dyns.iter()
                .find(|e| e.d_tag == goblin::elf::dynamic::DT_SONAME)
                .and_then(|e| elf.dynstrtab.get_at(e.d_val as usize))
                .map(|s| s.to_string())
        })
        .unwrap_or_default();

    // ── JNI metodları ─────────────────────────────────────────────
    let mut jni_methods = Vec::new();
    for sym in elf.dynsyms.iter() {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if let Some(mut jni) = parse_jni_symbol(name) {
                jni.address = sym.st_value;
                jni_methods.push(jni);
            }
        }
    }

    // ── Tehlikeli import'lar ──────────────────────────────────────
    let mut dangerous_imports = Vec::new();
    let mut all_imports: Vec<String> = Vec::new();

    for sym in elf.dynsyms.iter() {
        if sym.st_value == 0 {   // undefined = imported
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                all_imports.push(name.to_string());
                for &(pattern, category, severity) in DANGEROUS_IMPORTS {
                    if name.contains(pattern) {
                        dangerous_imports.push(DangerousImport {
                            symbol:      name.to_string(),
                            category:    category.to_string(),
                            severity:    severity.to_string(),
                            description: format!(
                                "Dangerous import '{}' detected in native library",
                                name
                            ),
                        });
                        break;
                    }
                }
            }
        }
    }

    // ── Exported symbols ──────────────────────────────────────────
    let exported: Vec<String> = elf.dynsyms.iter()
        .filter(|s| s.st_value != 0 && s.is_function())
        .filter_map(|s| elf.dynstrtab.get_at(s.st_name))
        .map(|n| n.to_string())
        .collect();

    // ── Linked libraries ──────────────────────────────────────────
    let linked_libs: Vec<String> = elf.libraries
        .iter()
        .map(|s| s.to_string())
        .collect();

    // ── Security flags ────────────────────────────────────────────
    let mut flags = HashMap::new();
    flags.insert("pie".to_string(),
        elf.header.e_type == goblin::elf::header::ET_DYN);
    flags.insert("nx".to_string(), {
        elf.program_headers.iter().any(|ph| {
            ph.p_type == goblin::elf::program_header::PT_GNU_STACK
            && (ph.p_flags & goblin::elf::program_header::PF_X) == 0
        })
    });
    flags.insert("relro".to_string(), {
        elf.program_headers.iter().any(|ph| {
            ph.p_type == goblin::elf::program_header::PT_GNU_RELRO
        })
    });
    flags.insert("canary".to_string(), {
        all_imports.iter().any(|s| s.contains("__stack_chk"))
    });
    flags.insert("fortify".to_string(), {
        all_imports.iter().any(|s| s.contains("_chk"))
    });
    flags.insert("stripped".to_string(), {
        !elf.section_headers.iter().any(|sh| {
            elf.shdr_strtab.get_at(sh.sh_name)
                .map(|n| n == ".symtab")
                .unwrap_or(false)
        })
    });

    // ── String hints (güvenlik ile ilgili kısa string'ler) ────────
    let string_hints: Vec<String> = Vec::new();
    // String extraction parallel_scan.rs'de yapılıyor

    Some(ElfDeepResult {
        soname,
        arch,
        jni_methods,
        dangerous_imports,
        exported_symbols: exported,
        linked_libs,
        security_flags: flags,
        string_hints,
    })
}

// ── Python binding ────────────────────────────────────────────────
#[pyfunction]
#[pyo3(name = "analyze_elf_deep")]
pub fn analyze_elf_deep_py(path: &str) -> PyResult<PyObject> {
    let data = fs::read(path).map_err(|e| {
        pyo3::exceptions::PyIOError::new_err(format!("Cannot read {}: {}", path, e))
    })?;

    Python::with_gil(|py| {
        let result_dict = pyo3::types::PyDict::new(py);

        match analyze_elf_deep(&data) {
            None => {
                result_dict.set_item("valid", false)?;
                return Ok(result_dict.into());
            }
            Some(r) => {
                result_dict.set_item("valid",  true)?;
                result_dict.set_item("soname", &r.soname)?;
                result_dict.set_item("arch",   &r.arch)?;

                // JNI methods
                let jni_list = pyo3::types::PyList::empty(py);
                for m in &r.jni_methods {
                    let d = pyo3::types::PyDict::new(py);
                    d.set_item("symbol",      &m.symbol)?;
                    d.set_item("java_class",  &m.java_class)?;
                    d.set_item("java_method", &m.java_method)?;
                    d.set_item("address",     m.address)?;
                    jni_list.append(d)?;
                }
                result_dict.set_item("jni_methods", jni_list)?;

                // Dangerous imports
                let imp_list = pyo3::types::PyList::empty(py);
                for i in &r.dangerous_imports {
                    let d = pyo3::types::PyDict::new(py);
                    d.set_item("symbol",      &i.symbol)?;
                    d.set_item("category",    &i.category)?;
                    d.set_item("severity",    &i.severity)?;
                    d.set_item("description", &i.description)?;
                    imp_list.append(d)?;
                }
                result_dict.set_item("dangerous_imports", imp_list)?;

                // Security flags
                let flags_dict = pyo3::types::PyDict::new(py);
                for (k, v) in &r.security_flags {
                    flags_dict.set_item(k, v)?;
                }
                result_dict.set_item("security_flags", flags_dict)?;
                result_dict.set_item("linked_libs",      r.linked_libs)?;
                result_dict.set_item("exported_count",   r.exported_symbols.len())?;
                result_dict.set_item("jni_count",        r.jni_methods.len())?;
                result_dict.set_item("dangerous_count",  r.dangerous_imports.len())?;
            }
        }
        Ok(result_dict.into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_jni_symbol_valid() {
        let r = parse_jni_symbol("Java_com_game_AntiCheat_checkRoot");
        assert!(r.is_some());
        let m = r.unwrap();
        assert_eq!(m.java_method, "checkRoot");
        assert!(m.java_class.contains("AntiCheat"));
    }

    #[test]
    fn test_parse_jni_symbol_invalid() {
        assert!(parse_jni_symbol("normalFunction").is_none());
        assert!(parse_jni_symbol("Java_").is_none());
    }

    #[test]
    fn test_invalid_elf_returns_none() {
        assert!(analyze_elf_deep(b"not an elf").is_none());
    }

    #[test]
    fn test_empty_returns_none() {
        assert!(analyze_elf_deep(b"").is_none());
    }
}
