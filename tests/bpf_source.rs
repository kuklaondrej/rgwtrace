const RGWTRACE_BPF: &str = include_str!("../bpf/rgwtrace.bpf.c");
const BPF_UTILS: &str = include_str!("../bpf/bpf_utils.h");
const DWARF_NATIVE: &str = include_str!("../src/dwarf_native.rs");

#[test]
fn object_name_read_uses_verifier_bounded_length() {
    assert!(RGWTRACE_BPF.contains("__u32 read_len = 0;"));
    assert!(RGWTRACE_BPF.contains("read_len = MAX_OBJECT_NAME - 1;"));
    assert!(RGWTRACE_BPF.contains("read_len &= MAX_OBJECT_NAME - 1;"));
    assert!(RGWTRACE_BPF.contains("asm volatile(\"%0 &= 127\" : \"+r\"(read_len));"));
    assert!(RGWTRACE_BPF
        .contains("rgwtrace_probe_read_user(event->object_name, read_len, (void *)name_base)"));
    assert!(!RGWTRACE_BPF
        .contains("bpf_probe_read_user(event->object_name, name_len, (void *)name_base)"));
}

#[test]
fn bpf_records_drop_and_probe_read_diagnostics() {
    assert!(RGWTRACE_BPF.contains("BPF_MAP_TYPE_PERCPU_ARRAY"));
    assert!(RGWTRACE_BPF.contains("RGWTRACE_DIAG_RINGBUF_REQUEST_DROPS"));
    assert!(RGWTRACE_BPF.contains("RGWTRACE_DIAG_RINGBUF_RADOS_DROPS"));
    assert!(RGWTRACE_BPF.contains("RGWTRACE_DIAG_RADOS_MAP_DROPS"));
    assert!(RGWTRACE_BPF.contains("RGWTRACE_DIAG_PROBE_READ_FAILURES"));
    assert!(RGWTRACE_BPF.contains("count_diag(RGWTRACE_DIAG_RINGBUF_RADOS_DROPS)"));
    assert!(BPF_UTILS.contains("rgwtrace_probe_read_user"));
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
