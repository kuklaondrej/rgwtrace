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
fn state_maps_use_lru_hash_to_bound_entry_leaks() {
    // rados_ops and rgw_requests accumulate entries that are only removed on a
    // clean finish/exit path. Entries for cancelled ops, linger/watch ops, or
    // exited worker threads never get deleted, so a plain HASH would fill up and
    // start hard-failing (E2BIG) on new inserts, silently killing correlation.
    // LRU_HASH evicts stale entries under pressure instead.
    assert!(RGWTRACE_BPF.contains(concat!(
        "  __uint(type, BPF_MAP_TYPE_LRU_HASH);\n",
        "  __type(key, struct client_op_key);\n",
        "  __type(value, struct rados_op_state);\n",
        "  __uint(max_entries, 8192);\n",
        "} rados_ops SEC(\".maps\");"
    )));
    assert!(RGWTRACE_BPF.contains(concat!(
        "  __uint(type, BPF_MAP_TYPE_LRU_HASH);\n",
        "  __type(key, __u32);\n",
        "  __type(value, struct rgw_request_ctx);\n",
        "  __uint(max_entries, 8192);\n",
        "} rgw_requests SEC(\".maps\");"
    )));
}

#[test]
fn reqstate_bridge_map_is_declared_lru_hash() {
    // Stage 1 of the cross-thread correlation bridge: a PID-scoped
    // (req_state*, tgid)-keyed LRU_HASH context map. Populated only; nothing
    // reads it yet, so there is no behavior change.
    assert!(RGWTRACE_BPF.contains(concat!(
        "struct reqstate_key {\n",
        "  __u64 req_state_ptr;\n",
        "  __u32 tgid;\n",
        "  __u32 _pad;\n",
        "};"
    )));
    assert!(RGWTRACE_BPF.contains(concat!(
        "  __uint(type, BPF_MAP_TYPE_LRU_HASH);\n",
        "  __type(key, struct reqstate_key);\n",
        "  __type(value, struct rgw_request_ctx);\n",
        "  __uint(max_entries, 8192);\n",
        "} rgw_ctx_by_reqstate SEC(\".maps\");"
    )));
}

#[test]
fn fetch_param_ptr_is_register_only_and_fails_closed_on_stack() {
    // Register-only raw-pointer descriptor helper: returns 0 for a
    // stack-located varloc so callers fail closed, and never composes a varloc
    // via fetch_var_member_addr.
    assert!(BPF_UTILS.contains("fetch_param_ptr"));
    assert!(BPF_UTILS.contains("if (vf == 0 || vf->varloc.stack)\n    return 0;"));
    assert!(BPF_UTILS.contains("return fetch_register(ctx, vf->varloc.reg);"));
}

#[test]
fn get_handler_populates_reqstate_bridge() {
    // The get_handler probe writes the reqstate bridge, reusing the slot-30
    // base register value (register-only), and counts update failures.
    assert!(
        RGWTRACE_BPF.contains("bpf_map_update_elem(&rgw_ctx_by_reqstate, &rkey, request, BPF_ANY)")
    );
    assert!(RGWTRACE_BPF.contains("request->req_state_ptr = req_state_base;"));
    assert!(RGWTRACE_BPF.contains("if (req_state_is_reg && req_state_base > 0)"));
    assert!(RGWTRACE_BPF.contains("count_diag(RGWTRACE_DIAG_REQSTATE_MAP_DROPS)"));
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
