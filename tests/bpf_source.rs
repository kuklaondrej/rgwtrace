const RGWTRACE_BPF: &str = include_str!("../bpf/rgwtrace.bpf.c");
const RGWTRACE_EVENTS: &str = include_str!("../bpf/rgwtrace_events.h");
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
fn bpf_emits_only_request_end_marker() {
    // Single-marker contract: the get_handler entry probe is the only safe
    // request probe and emits exactly one request marker (END), which carries
    // both the seeded start_ns and the probe-time end_ns. REQUEST_START is
    // deliberately NOT emitted -- it would be informationally redundant (the
    // END already carries start_ns), double ring-buffer volume, and a matched
    // start/end lifecycle is unattainable without a request-completion probe.
    assert!(RGWTRACE_BPF.contains("emit_request_event(RGWTRACE_EVENT_REQUEST_END"));
    assert!(!RGWTRACE_BPF.contains("RGWTRACE_EVENT_REQUEST_START"));
    // AGENTS.md hard rule: no return probe anywhere (a process_request return
    // probe was observed to crash RGW live). Guard against any uretprobe or a
    // probe handler attached to process_request being reintroduced.
    assert!(!RGWTRACE_BPF.contains("uretprobe"));
    assert!(!RGWTRACE_BPF.contains("uprobe_process_request"));
    assert!(!RGWTRACE_BPF.contains("int uprobe_ret_"));
}

#[test]
fn bpf_records_rados_sender_thread_id() {
    assert!(RGWTRACE_EVENTS.contains("__u32 send_tid;"));
    assert!(RGWTRACE_BPF.contains("__u32 thread_id = get_tid();"));
    assert!(RGWTRACE_BPF.contains("event->send_tid = thread_id;"));
}

#[test]
fn cls_and_method_reads_use_verifier_bounded_lengths() {
    assert!(RGWTRACE_BPF.contains("__u32 cls_read_len = cls_len;"));
    assert!(RGWTRACE_BPF.contains("cls_read_len &= sizeof(event->cls_ops[i].cls_name) - 1;"));
    assert!(RGWTRACE_BPF.contains("asm volatile(\"%0 &= 7\" : \"+r\"(cls_read_len));"));
    assert!(RGWTRACE_BPF.contains("__u32 method_read_len = method_len;"));
    assert!(RGWTRACE_BPF.contains("method_read_len &= sizeof(event->cls_ops[i].method_name) - 1;"));
    assert!(RGWTRACE_BPF.contains("asm volatile(\"%0 &= 31\" : \"+r\"(method_read_len));"));
    assert!(!RGWTRACE_BPF.contains("event->cls_ops[i].cls_name, cls_len"));
    assert!(!RGWTRACE_BPF.contains("event->cls_ops[i].method_name, method_len"));
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
