const RGWTRACE_BPF: &str = include_str!("../bpf/rgwtrace.bpf.c");
const DWARF_NATIVE: &str = include_str!("../src/dwarf_native.rs");

#[test]
fn object_name_read_uses_verifier_bounded_length() {
    assert!(RGWTRACE_BPF.contains("__u32 read_len = 0;"));
    assert!(RGWTRACE_BPF.contains("read_len = MAX_OBJECT_NAME - 1;"));
    assert!(RGWTRACE_BPF.contains("read_len &= MAX_OBJECT_NAME - 1;"));
    assert!(RGWTRACE_BPF.contains("asm volatile(\"%0 &= 127\" : \"+r\"(read_len));"));
    assert!(RGWTRACE_BPF
        .contains("bpf_probe_read_user(event->object_name, read_len, (void *)name_base)"));
    assert!(!RGWTRACE_BPF
        .contains("bpf_probe_read_user(event->object_name, name_len, (void *)name_base)"));
}

#[test]
fn dwarf_native_demangling_uses_fallible_api() {
    let normalized = DWARF_NATIVE.split_whitespace().collect::<String>();
    assert!(normalized.contains("symbol.demangle(&cpp_demangle::DemangleOptions::default()).ok()?"));
    assert!(!DWARF_NATIVE.contains("symbol.to_string()"));
}

#[test]
fn dwarf_native_symbol_lookup_ignores_local_non_text_symbols() {
    assert!(DWARF_NATIVE.contains("!symbol.is_global()"));
    assert!(DWARF_NATIVE.contains("symbol.kind() != SymbolKind::Text"));
}
