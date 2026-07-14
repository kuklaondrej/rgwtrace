const RGWTRACE_BPF: &str = include_str!("../bpf/rgwtrace.bpf.c");
const RGWTRACE_EVENTS: &str = include_str!("../bpf/rgwtrace_events.h");
const BPF_UTILS: &str = include_str!("../bpf/bpf_utils.h");
const DWARF_NATIVE: &str = include_str!("../src/dwarf_native.rs");
const LIVE_LINUX: &str = include_str!("../src/live/linux.rs");
const CLI: &str = include_str!("../src/cli.rs");

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
fn bpf_emits_start_and_end_request_markers_from_entry_probes_only() {
    // Two-marker contract (supersedes the old single-marker one): get_handler
    // ENTRY opens the request with a START marker, and the req_state destructor
    // ENTRY closes it with an END marker carrying a REAL end_ns. The old model
    // emitted only an END from get_handler, whose end_ns was the marker's own
    // probe time -- i.e. the request's visible duration was fabricated in
    // userspace from its RADOS children.
    assert!(RGWTRACE_BPF.contains("emit_request_event(RGWTRACE_EVENT_REQUEST_START, request, 0)"));
    assert!(RGWTRACE_BPF.contains("emit_request_event(RGWTRACE_EVENT_REQUEST_END, bridged,"));
    // AGENTS.md hard rule, and the reason the END probe is on the destructor
    // (an entry probe) rather than a process_request return probe: uretprobes
    // patch the return address on the stack and asio switches fiber stacks
    // underneath the probe, which crashed RGW live. No return probe, anywhere.
    // `SEC("uretprobe"...)` is the ONLY way to declare a return probe in BPF C,
    // so the ban is asserted on the section attribute rather than on the word
    // (the handler comments must stay free to explain why it is banned).
    assert!(!RGWTRACE_BPF.contains("SEC(\"uretprobe"));
    assert!(!RGWTRACE_BPF.contains("uprobe_process_request"));
    assert!(!RGWTRACE_BPF.contains("int uprobe_ret_"));
    // Every probe is attached as an ENTRY uprobe: each `&skel.progs.uprobe_*`
    // attach argument is immediately followed by `retprobe = false`.
    for (idx, _) in LIVE_LINUX.match_indices("&skel.progs.uprobe_") {
        let tail = &LIVE_LINUX[idx..(idx + 80).min(LIVE_LINUX.len())];
        assert!(
            tail.contains("false"),
            "probe attach must pass retprobe = false: {tail}"
        );
        assert!(
            !tail.contains("true"),
            "no probe may ever be attached as a uretprobe: {tail}"
        );
    }
    assert!(!LIVE_LINUX.contains("attach_uprobe(prog, true"));
}

#[test]
fn request_end_probe_reads_this_and_emits_a_real_end() {
    // The END probe resolves the `this` (req_state*) raw-pointer descriptor from
    // hprobe slot 50, register-only, looks the request up in the (req_state*,
    // tgid) bridge, and emits a REQUEST_END stamped with the destructor's own
    // clock read -- the request's true end.
    assert!(RGWTRACE_BPF.contains("int uprobe_rgw_req_state_dtor(struct pt_regs *ctx)"));
    assert!(RGWTRACE_BPF.contains("int varid = 50;"));
    assert!(RGWTRACE_BPF.contains("__u64 rsp = fetch_param_ptr(ctx, vf);"));
    assert!(RGWTRACE_BPF.contains("bpf_ktime_get_boot_ns()"));
    // It is the first and only delete on the insert-only bridge map: the end of
    // a request is exactly when its bridge entry stops being needed, so the map
    // is now bounded by lifecycle rather than by LRU eviction alone.
    assert!(RGWTRACE_BPF.contains("bpf_map_delete_elem(&rgw_ctx_by_reqstate, &rkey)"));
}

#[test]
fn request_end_probe_only_clears_its_own_thread_context() {
    // RGW/Beast pool threads are shared: after a coroutine migration the context
    // sitting on this tid may belong to ANOTHER in-flight request. The end probe
    // must therefore clear rgw_requests[tid] only when the context is provably
    // this request's own (same req_state*, same process) -- clearing another
    // live request's context would silently un-correlate its RADOS ops.
    assert!(RGWTRACE_BPF.contains("cur != 0 && cur->req_state_ptr == rsp && cur->pid == tgid"));
}

#[test]
fn request_end_probe_wires_coverage_counters() {
    assert!(RGWTRACE_BPF.contains("count_diag(RGWTRACE_DIAG_REQUEST_END_HITS)"));
    assert!(RGWTRACE_BPF.contains("count_diag(RGWTRACE_DIAG_REQUEST_END_MISSES)"));
    assert!(RGWTRACE_BPF.contains("count_diag(RGWTRACE_DIAG_REQUEST_END_BASE_UNRESOLVED)"));
    // ABI mirror: the end-probe counters keep their slots, and the _send_op
    // liveness-gate counters take the next two, with the total bumped to match.
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_REQUEST_END_HITS = 10,"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_REQUEST_END_MISSES = 11,"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_REQUEST_END_BASE_UNRESOLVED = 12,"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_SENDOP_STALE_CTX_DROPS = 13,"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_SENDOP_UNVERIFIABLE_CTX = 14,"));
    // Phase B appends its counters after them, then the fail-closed and multi-key
    // counters. Every existing slot is load-bearing (userspace reads each counter
    // by INDEX in src/live/linux.rs), so they must never be renumbered -- new
    // counters may only be APPENDED, and the total moved to match.
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_OPERATE_SEED_HITS = 15,"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_SENDOP_UNBRIDGED_CTX_DROPS = 18,"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_OPERATE_MISS_CTX_CLEARED = 19,"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_RGWOP_KEY_INSERTS = 20,"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_RGWOP_KEY_REVOKES = 21,"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_RGWOP_KEY_REVOKE_SKIPPED = 22,"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_RGWOP_KEY_UNRESOLVED = 23,"));
    // The per-key seed-hit split (which key did the dpp match?), the unresolved-dpp
    // fail-closed clear, and the rest of the revocation accounting are APPENDED
    // after them, again without renumbering anything.
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_OPERATE_SEED_HITS_REQSTATE = 24,"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_OPERATE_SEED_HITS_RGWOP = 25,"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_OPERATE_SEED_HITS_UNATTRIBUTED = 26,"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_OPERATE_UNRESOLVED_CTX_CLEARED = 27,"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_RGWOP_KEY_REVOKE_ABSENT = 28,"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_RGWOP_KEY_INDEX_DROPS = 29,"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_RGWOP_KEY_DISABLED = 30,"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_COUNTERS = 31,"));
}

#[test]
fn send_op_validates_request_context_liveness_before_stamping() {
    // A request's context is COPIED onto every thread it is seeded/re-seeded
    // onto, and the destructor can only revoke the copy on the thread it runs
    // on. Every other copy outlives its request, so _send_op MUST re-validate a
    // context against the (req_state*, tgid) bridge -- deleted exactly at request
    // end -- before stamping its trans_id onto an op. Without this, an op
    // submitted later from such a thread inherits a DEAD request's identity and
    // is confidently attributed to the wrong request.
    assert!(RGWTRACE_BPF
        .contains("static __always_inline int request_ctx_is_live(struct rgw_request_ctx *ctx)"));
    assert!(RGWTRACE_BPF.contains("if (request != 0 && request_ctx_is_live(request))"));
    // Presence alone is NOT sufficient: req_state is stack-allocated in
    // process_request, so its address is recycled by the next request on the
    // same worker thread. The bridged entry's identity (the get_handler clock
    // read + thread) must match the copy, or a recycled address would validate a
    // dead context against a NEW request's entry.
    assert!(RGWTRACE_BPF.contains(concat!(
        "  if (bridged == 0 || bridged->start_ns != ctx->start_ns ||\n",
        "      bridged->tid != ctx->tid) {"
    )));
    // Fail-closed and counted, never silent.
    assert!(RGWTRACE_BPF.contains("count_diag(RGWTRACE_DIAG_SENDOP_STALE_CTX_DROPS)"));
    assert!(RGWTRACE_BPF.contains("count_diag(RGWTRACE_DIAG_SENDOP_UNVERIFIABLE_CTX)"));
}

#[test]
fn liveness_gate_is_disabled_when_the_end_probe_is_not_attached() {
    // The END probe is the ONLY deleter of bridge entries, so with it absent
    // "entry present" carries no liveness information: the gate is switched off
    // (via a userspace-written global) and _send_op keeps its previous behavior,
    // rather than paying for a lookup that can only answer "alive".
    assert!(RGWTRACE_BPF.contains("volatile __u32 REQUEST_END_PROBE_ATTACHED = 0;"));
    assert!(RGWTRACE_BPF.contains("  if (REQUEST_END_PROBE_ATTACHED == 0) {"));
    // Userspace sets it from the ACTUAL attach outcome, not from intent...
    assert!(LIVE_LINUX
        .contains("skel.maps.bss_data.REQUEST_END_PROBE_ATTACHED = u32::from(request_end_probe);"));
    // ...and it is published as an ORDERED attach step, not after everything is
    // already attached. See `attach_order_never_lets_a_bridge_entry_outlive_its_revoker`.
    assert!(LIVE_LINUX.contains("AttachStep::PublishBpfConfig => {"));
}

#[test]
fn the_bpf_config_is_published_between_the_revoker_and_the_first_bridge_probe() {
    // FINDING (attach ordering): get_handler used to attach BEFORE the destructor
    // probe, and REQUEST_END_PROBE_ATTACHED was only written after EVERY probe was
    // up. A request could therefore pass get_handler -- creating its canonical
    // bridge entry -- and COMPLETE before its destructor probe existed. Nothing
    // would ever revoke that entry; it would sit in the bridge for the whole run;
    // and the moment the flag flipped to 1 it would start PASSING the liveness
    // gate's identity check, letting a later submit inherit a DEAD request's
    // trans_id. Permanent, and a mis-correlation.
    //
    // The order is now DATA (`ATTACH_ORDER`), the attach loop is driven by it, and
    // `validate_attach_order` rejects any reordering that could strand an entry.
    assert!(LIVE_LINUX.contains("const ATTACH_ORDER: [AttachStep; 6] = ["));
    assert!(LIVE_LINUX.contains("fn validate_attach_order(steps: &[AttachStep]) -> Result<()> {"));
    assert!(LIVE_LINUX.contains("    validate_attach_order(&ATTACH_ORDER)?;"));
    assert!(LIVE_LINUX.contains("    for step in ATTACH_ORDER {"));

    // The revoker is first, the config it feeds is second, and every producer /
    // consumer of a bridge entry comes after both.
    let order_start = LIVE_LINUX
        .find("const ATTACH_ORDER: [AttachStep; 6] = [")
        .expect("attach order");
    let order = &LIVE_LINUX[order_start..];
    let order = &order[..order.find("];").expect("attach order ends")];
    let position = |step: &str| {
        order
            .find(step)
            .unwrap_or_else(|| panic!("{step} in order"))
    };
    let revoker = position("AttachStep::RequestEndProbe");
    let config = position("AttachStep::PublishBpfConfig");
    for producer_or_consumer in [
        "AttachStep::GetHandler",
        "AttachStep::ProcessAuthenticated",
        "AttachStep::RadosOperate",
        "AttachStep::ObjecterOps",
    ] {
        assert!(
            revoker < position(producer_or_consumer) && config < position(producer_or_consumer),
            "{producer_or_consumer} must attach after the request-END probe and after the config \
             that gates it -- otherwise a bridge entry can exist with no revoker"
        );
    }
}

#[test]
fn the_rgw_op_bridge_key_can_be_disabled_at_runtime_without_a_rebuild() {
    // The `RGWOp*` alternate key is INSURANCE, and it is the one part of the design
    // carrying a mis-correlation hazard that pointer identity cannot close (the S3
    // website retarget: the RGWOp is freed and replaced while its request is still
    // ALIVE, so the liveness gate would pass an impostor at the recycled address).
    // Whether it earns that risk is a MEASUREMENT -- so it must be switchable
    // without a rebuild, and the measurement must be in the run summary.
    assert!(RGWTRACE_BPF.contains("volatile __u32 RGW_OP_BRIDGE_KEY_ENABLED = 0;"));
    assert!(RGWTRACE_BPF.contains("  if (RGW_OP_BRIDGE_KEY_ENABLED != 0) {"));
    assert!(RGWTRACE_BPF.contains("count_diag(RGWTRACE_DIAG_RGWOP_KEY_DISABLED)"));
    assert!(LIVE_LINUX
        .contains("skel.maps.bss_data.RGW_OP_BRIDGE_KEY_ENABLED = u32::from(rgw_op_bridge_key);"));
    assert!(CLI.contains("pub disable_rgw_op_bridge_key: bool,"));

    // The measurement itself: seed hits split by WHICH key matched. The dpp is
    // compared against the bridged value's own keys, so the attribution is exact.
    assert!(RGWTRACE_BPF
        .contains("  if (bridged->req_state_ptr == dpp)\n    via = BRIDGE_SEED_VIA_REQSTATE;"));
    assert!(RGWTRACE_BPF
        .contains("  else if (bridged->rgw_op_ptr == dpp)\n    via = BRIDGE_SEED_VIA_RGWOP;"));
    assert!(RGWTRACE_BPF.contains("count_diag(RGWTRACE_DIAG_OPERATE_SEED_HITS_REQSTATE)"));
    assert!(RGWTRACE_BPF.contains("count_diag(RGWTRACE_DIAG_OPERATE_SEED_HITS_RGWOP)"));
    assert!(RGWTRACE_BPF.contains("count_diag(RGWTRACE_DIAG_OPERATE_SEED_HITS_UNATTRIBUTED)"));
}

#[test]
fn an_unbridged_context_fails_closed_when_the_end_probe_is_attached() {
    // A context with NO req_state* (get_handler could not resolve it from a
    // register on this build) can never be found through the bridge -- so the
    // destructor's lookup misses and returns BEFORE clearing it off the thread, and
    // it lingers on a pooled thread for the rest of the run. It used to be treated
    // as proof of life ("only get_handler can have put it here"), which let a
    // long-dead request stamp later ops on that thread.
    //
    // With a revoking END probe present, an unverifiable context is now DROPPED.
    // The fail-open path survives ONLY for the no-end-probe build, where nothing
    // revokes anything and the gate is off entirely.
    assert!(RGWTRACE_BPF.contains(concat!(
        "  if (ctx->req_state_ptr == 0) {\n",
        "    count_diag(RGWTRACE_DIAG_SENDOP_UNBRIDGED_CTX_DROPS);\n",
        "    return 0;\n",
        "  }"
    )));
    // ...and it is never silent: userspace warns at attach when get_handler cannot
    // hold the req_state* in a register, because that build then correlates NOTHING.
    assert!(LIVE_LINUX.contains("fn warn_if_req_state_is_not_bridgeable("));
    assert!(LIVE_LINUX.contains("dwarf.get_handler_req_state_is_register_resolvable(&module)"));
}

#[test]
fn request_end_probe_attach_is_optional_fails_soft_and_is_never_silent() {
    // Backward compatibility: a build whose destructor address, variant
    // provenance, or `this` descriptor cannot be resolved must keep working with
    // derived durations. The attach failure is warned about, never propagated
    // (contrast `attach_if_present(...)?` elsewhere) -- but it is also never
    // SKIPPED SILENTLY: a missing end probe silently changes what every request
    // duration in the output means, so the operator is told at attach time.
    assert!(LIVE_LINUX.contains("fn attach_request_end_probe("));
    assert!(LIVE_LINUX.contains(") -> AttachOutcome {"));
    assert!(LIVE_LINUX.contains("RequestEndProbe::Unavailable(gap) => {"));
    assert!(LIVE_LINUX.contains(
        "request-END probe unavailable; request span durations will be DERIVED from RADOS \\"
    ));
    assert!(LIVE_LINUX.contains(
        "                    attach_request_end_probe(&mut links, skel, dwarf, &targets.radosgw, pid)\n                        == AttachOutcome::Attached;"
    ));
    // The end probe's address comes from the provenance-checked accessor, never
    // from the generic `function_addr` path that cannot prove the variant.
    assert!(LIVE_LINUX.contains("dwarf.request_end_probe(&module)"));
}

#[test]
fn reseed_body_is_shared_with_the_end_probe_path() {
    // The bridge lookup + rgw_requests seed lives in one __always_inline helper so
    // the Phase B rgw_rados_operate seed uses it verbatim. (The
    // rgw_process_authenticated probe now open-codes the lookup instead of calling
    // the helper, because it must also WRITE the alternate RGWOp* key into the
    // bridge value -- but it seeds from the same stack copy, in the same way.)
    assert!(RGWTRACE_BPF
        .contains("static __always_inline int reseed_thread_from_reqstate(__u64 dpp, __u32 tgid,"));
    // The helper now reports WHICH key the dpp matched (BRIDGE_SEED_MISS, or the
    // canonical/alternate key), because that split is what decides the alternate
    // key's fate. A miss is still the zero value, so the fail-closed branch is the
    // same branch it always was.
    assert!(RGWTRACE_BPF.contains("int via = reseed_thread_from_reqstate(dpp, tgid, tid);"));
    assert!(RGWTRACE_BPF.contains("if (via != BRIDGE_SEED_MISS) {"));
    assert!(RGWTRACE_BPF.contains("#define BRIDGE_SEED_MISS 0"));
    assert!(RGWTRACE_BPF.contains("__builtin_memcpy(&ctx_copy, bridged, sizeof(ctx_copy));"));
    assert!(RGWTRACE_BPF.contains("bpf_map_update_elem(&rgw_requests, &tid, &ctx_copy, BPF_ANY)"));
}

#[test]
fn bpf_records_rados_sender_thread_id() {
    assert!(RGWTRACE_EVENTS.contains("__u32 send_tid;"));
    assert!(RGWTRACE_BPF.contains("__u32 thread_id = get_tid();"));
    assert!(RGWTRACE_BPF.contains("event->send_tid = thread_id;"));
}

#[test]
fn lifecycle_state_maps_use_plain_hash_not_lru() {
    // rados_ops and rgw_requests MUST stay plain HASH, never LRU_HASH. Do not
    // "fix" this back to LRU to bound leaks: BPF LRU_HASH reserves ~128 free
    // nodes per logical CPU, so on many-core hosts (>=64 CPUs) 128*cores
    // approaches max_entries and the allocator evicts LIVE, in-flight entries
    // once >~128 ops are outstanding. An evicted rados_ops entry makes
    // _finish_op's lookup miss and the op event is NEVER emitted -- production
    // traces showed request markers with zero rados children. Both maps have
    // explicit lifecycle deletes; plain HASH only rejects new inserts when full
    // (counted via the existing drop counters), which is strictly less harmful.
    assert!(RGWTRACE_BPF.contains(concat!(
        "  __uint(type, BPF_MAP_TYPE_HASH);\n",
        "  __type(key, struct client_op_key);\n",
        "  __type(value, struct rados_op_state);\n",
        "  __uint(max_entries, 8192);\n",
        "} rados_ops SEC(\".maps\");"
    )));
    assert!(RGWTRACE_BPF.contains(concat!(
        "  __uint(type, BPF_MAP_TYPE_HASH);\n",
        "  __type(key, __u32);\n",
        "  __type(value, struct rgw_request_ctx);\n",
        "  __uint(max_entries, 8192);\n",
        "} rgw_requests SEC(\".maps\");"
    )));
    // Neither map may be declared LRU_HASH.
    assert!(!RGWTRACE_BPF.contains(concat!(
        "  __uint(type, BPF_MAP_TYPE_LRU_HASH);\n",
        "  __type(key, struct client_op_key);\n",
        "  __type(value, struct rados_op_state);\n",
    )));
    assert!(!RGWTRACE_BPF.contains(concat!(
        "  __uint(type, BPF_MAP_TYPE_LRU_HASH);\n",
        "  __type(key, __u32);\n",
        "  __type(value, struct rgw_request_ctx);\n",
    )));
    // The cross-thread bridge, by contrast, STAYS LRU_HASH: its consumers fail
    // closed on a missing entry, so eviction degrades correlation instead of
    // corrupting it, and it still needs a growth bound on a build whose END probe
    // (its only deleter) could not attach.
    assert!(RGWTRACE_BPF.contains(concat!(
        "  __uint(type, BPF_MAP_TYPE_LRU_HASH);\n",
        "  __type(key, struct reqstate_key);\n",
        "  __type(value, struct rgw_request_ctx);\n",
        "  __uint(max_entries, 131072);\n",
        "} rgw_ctx_by_reqstate SEC(\".maps\");"
    )));
}

#[test]
fn reqstate_bridge_map_is_declared_lru_hash_and_sized_for_multi_key_on_many_core_hosts() {
    // Cross-thread correlation bridge: a PID-scoped (pointer, tgid)-keyed LRU_HASH
    // context map, holding TWO keys per in-flight request (its req_state* and the
    // RGWOp* executing it).
    //
    // Sizing is a many-core question, not a request-rate one: BPF's LRU_HASH
    // reserves ~128 free nodes per CPU that touches the map, and a map whose
    // capacity those reservations approach evicts LIVE entries (the regression that
    // forced rados_ops/rgw_requests back to plain HASH). 131072 keeps the
    // reservation a small fraction even at 256 CPUs (32768 nodes) and still leaves
    // ~49k concurrent requests -- i.e. the multi-key design did NOT eat the
    // per-request headroom, it doubled the map to preserve it.
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
        "  __uint(max_entries, 131072);\n",
        "} rgw_ctx_by_reqstate SEC(\".maps\");"
    )));
    // 128 nodes/CPU * 256 CPUs must stay well under capacity, with room for the
    // two keys every in-flight request occupies.
    const LRU_FREELIST_PER_CPU: u32 = 128;
    const WIDE_HOST_CPUS: u32 = 256;
    const MAX_ENTRIES: u32 = 131072;
    const KEYS_PER_REQUEST: u32 = 2;
    let usable = MAX_ENTRIES - LRU_FREELIST_PER_CPU * WIDE_HOST_CPUS;
    assert!(
        usable / KEYS_PER_REQUEST >= 32_768,
        "a 256-CPU host must still hold tens of thousands of in-flight requests: {usable} usable"
    );
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
fn reseed_probe_reads_raw_pointer_and_bridges_context() {
    // Stage 3 consumer: the rgw_process_authenticated uprobe fetches the
    // req_state* raw-pointer descriptor (varid 40, register-only via
    // fetch_param_ptr) and re-seeds rgw_requests on a bridge hit.
    assert!(RGWTRACE_BPF.contains("int uprobe_rgw_process_authenticated(struct pt_regs *ctx)"));
    assert!(RGWTRACE_BPF.contains("int varid = 40;"));
    assert!(RGWTRACE_BPF.contains("__u64 rsp = fetch_param_ptr(ctx, vf);"));
    assert!(RGWTRACE_BPF.contains("bpf_map_lookup_elem(&rgw_ctx_by_reqstate, &rkey)"));
    assert!(RGWTRACE_BPF.contains("bpf_map_update_elem(&rgw_requests, &tid, &ctx_copy, BPF_ANY)"));
}

#[test]
fn reseed_probe_fails_closed_on_miss_with_identity_check() {
    // On a bridge miss the probe clears a FOREIGN lingering context
    // (mismatched req_state* OR mismatched tgid) so _send_op cannot stamp a
    // stale trans_id, while keeping this request's own context.
    assert!(RGWTRACE_BPF.contains("cur != 0 && (cur->req_state_ptr != rsp || cur->pid != tgid)"));
    assert!(RGWTRACE_BPF.contains("bpf_map_delete_elem(&rgw_requests, &tid)"));
}

#[test]
fn reseed_probe_wires_coverage_counters() {
    assert!(RGWTRACE_BPF.contains("count_diag(RGWTRACE_DIAG_RESEED_BASE_UNRESOLVED)"));
    assert!(RGWTRACE_BPF.contains("count_diag(RGWTRACE_DIAG_RESEED_HITS)"));
    assert!(RGWTRACE_BPF.contains("count_diag(RGWTRACE_DIAG_RESEED_MISSES)"));
    // The hit path counts an update failure as a request-context drop, exactly
    // like the other rgw_requests writers.
    assert!(RGWTRACE_BPF.contains("count_diag(RGWTRACE_DIAG_REQUEST_CONTEXT_DROPS)"));
    // ABI mirror: the three re-seed counters keep their slots.
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_RESEED_HITS = 7,"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_RESEED_MISSES = 8,"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_RESEED_BASE_UNRESOLVED = 9,"));
}

#[test]
fn reseed_probe_attach_is_gated_behind_the_opt_in_flag() {
    // Every cross-thread re-seed probe -- the Stage-3 rgw_process_authenticated
    // one AND the Phase B per-submit rgw_rados_operate ones -- attaches only
    // inside the --correlate-cross-thread branch, so the flag-off path is
    // byte-for-byte identical (programs present but never attached). The
    // rgw_process_authenticated probe additionally requires its varid-40
    // descriptor to have resolved.
    assert!(LIVE_LINUX.contains(
        "if correlate_cross_thread && reseed_var_field_present(dwarf, &targets.radosgw)"
    ));
    assert!(LIVE_LINUX.contains("&skel.progs.uprobe_rgw_process_authenticated"));
    assert!(LIVE_LINUX
        .contains("attach_rados_operate_probes(&mut links, skel, dwarf, &targets.radosgw, pid);"));

    // Structural check that BOTH cross-thread attaches are behind the flag: each
    // sits inside its own `AttachStep` arm, and each arm's body is guarded by
    // `correlate_cross_thread`.
    let operate_arm = LIVE_LINUX
        .find("AttachStep::RadosOperate => {")
        .expect("phase B attach step");
    let operate_attach = LIVE_LINUX
        .find("attach_rados_operate_probes(&mut links,")
        .expect("phase B attach");
    let gate = LIVE_LINUX[operate_arm..operate_attach]
        .find("if correlate_cross_thread {")
        .expect("the rgw_rados_operate attach must sit behind --correlate-cross-thread");
    assert!(operate_arm + gate < operate_attach);
}

#[test]
fn rados_operate_seed_reads_the_dpp_and_never_dereferences_it() {
    // PHASE B. The per-submit re-seed reads `dpp` (arg0) register-only via the
    // raw-pointer descriptor and uses its VALUE as a bridge key. It must NEVER
    // read through it: RGW passes many non-req_state DoutPrefixProvider
    // implementations (bucket, zone, wrappers, background threads) to
    // rgw_rados_operate, and dereferencing an unknown concrete type is exactly the
    // object-graph-walking fragility the design rejected. A foreign dpp must
    // simply MISS the bridge.
    assert!(RGWTRACE_BPF.contains(
        "static __always_inline int rgw_rados_operate_seed(struct pt_regs *ctx, int varid)"
    ));
    assert!(RGWTRACE_BPF.contains("__u64 dpp = fetch_param_ptr(ctx, vf);"));

    // No memory is ever read through the dpp -- not directly, and not via the
    // member-deref helper (which is what would apply an inheritance offset).
    let seed = phase_b_seed_body();
    assert!(
        !seed.contains("fetch_var_member_addr"),
        "the dpp must never be composed into a member address: {seed}"
    );
    assert!(
        !seed.contains("bpf_probe_read"),
        "the dpp must never be dereferenced: {seed}"
    );
    assert!(
        !seed.contains("rgwtrace_probe_read"),
        "the dpp must never be dereferenced: {seed}"
    );
}

#[test]
fn rados_operate_seed_reuses_the_shared_reseed_helper() {
    // Phase B does not invent a second bridge, a second key, or a second seeding
    // path: `dpp` and `req_state*` are numerically equal (req_state inherits
    // DoutPrefixProvider at offset 0), so the existing (req_state*, tgid) bridge
    // and the existing helper apply verbatim.
    let seed = phase_b_seed_body();
    assert!(seed.contains("reseed_thread_from_reqstate(dpp, tgid, tid)"));
    // ...and therefore seeds rgw_requests with a COPY of the bridge value, which
    // is what makes the _send_op liveness gate pass for a Phase-B-seeded context.
    assert!(RGWTRACE_BPF.contains("bpf_map_update_elem(&rgw_requests, &tid, &ctx_copy, BPF_ANY)"));
}

#[test]
fn rados_operate_seed_fails_closed_by_clearing_context_on_a_foreign_dpp_miss() {
    // INVARIANT CHANGE (was: "must not clear on miss"). The old rule traded a
    // correctness loss for a coverage gain, which is the wrong trade for this tool.
    //
    // The hazard: request A runs an operate on pool thread T, so the seed leaves
    // A's context on T. A yields. Request B resumes on T and submits through a dpp
    // we cannot key -> miss. If the miss left T's context alone, A's context would
    // still be there; A is genuinely still ALIVE, so the _send_op liveness gate
    // would PASS it; and B's op would be stamped with A's trans_id. The gate proves
    // only that the cached request EXISTS, never that it is the coroutine running
    // here now -- and Phase B amplifies this, because it scatters A's context onto
    // every thread A ever ran an operate on.
    //
    // So a miss now DROPS whatever is on the thread: nothing this submit did not
    // prove is assumed. The cost (a request's own operate through a wrapper dpp
    // loses correlation) is counted, and it is small because the bridge is
    // multi-keyed: a request's own operates hit under its req_state* OR its RGWOp*.
    let seed = phase_b_seed_body();
    assert!(
        seed.contains("operate_drop_thread_ctx(tid, RGWTRACE_DIAG_OPERATE_MISS_CTX_CLEARED);"),
        "the per-submit seed must fail closed and clear thread context on a miss: {seed}"
    );
    assert!(
        RGWTRACE_BPF.contains(concat!(
            "static __always_inline void operate_drop_thread_ctx(__u32 tid, __u32 diag) {\n",
            "  if (bpf_map_lookup_elem(&rgw_requests, &tid) != 0) {\n",
            "    bpf_map_delete_elem(&rgw_requests, &tid);\n",
            "    count_diag(diag);\n",
            "  }\n",
            "}"
        )),
        "the coverage the fail-closed clear costs must be counted, never silent"
    );
    // The clear happens ONLY on the miss path -- a hit seeds and returns first.
    let hit = seed
        .find("count_diag(RGWTRACE_DIAG_OPERATE_SEED_HITS);")
        .expect("hit branch");
    let clear = seed
        .find("operate_drop_thread_ctx(tid, RGWTRACE_DIAG_OPERATE_MISS_CTX_CLEARED);")
        .expect("clear");
    assert!(hit < clear, "the hit path must return before the clear");
}

#[test]
fn an_unresolved_or_null_dpp_fails_closed_exactly_like_a_foreign_one() {
    // FINDING (fail-closed hole): a zero/unresolved `dpp` used to `return 0`
    // WITHOUT clearing the thread's context, while a resolved-but-foreign dpp
    // cleared it. That asymmetry was a mis-correlation source, not a coverage
    // choice: if thread T carries live request A's context and a submit arrives
    // with a null/unresolvable dpp, A's context survives, A is genuinely still
    // ALIVE so the liveness gate PASSES it, and the op -- which may belong to a
    // completely different coroutine now running on T -- is stamped as A.
    //
    // An unresolved dpp proves exactly as little as a foreign one. Both now clear.
    let seed = phase_b_seed_body();
    assert!(seed.contains(concat!(
        "  struct VarField *vf = bpf_map_lookup_elem(&hprobes, &varid);\n",
        "  if (vf == 0) {\n",
        "    count_diag(RGWTRACE_DIAG_OPERATE_BASE_UNRESOLVED);\n",
        "    operate_drop_thread_ctx(tid, RGWTRACE_DIAG_OPERATE_UNRESOLVED_CTX_CLEARED);\n",
        "    return 0;\n",
        "  }"
    )));
    assert!(seed.contains(concat!(
        "  __u64 dpp = fetch_param_ptr(ctx, vf);\n",
        "  if (dpp == 0) {\n",
        "    count_diag(RGWTRACE_DIAG_OPERATE_BASE_UNRESOLVED);\n",
        "    operate_drop_thread_ctx(tid, RGWTRACE_DIAG_OPERATE_UNRESOLVED_CTX_CLEARED);\n",
        "    return 0;\n",
        "  }"
    )));
    // Counted DISTINCTLY from the foreign-dpp miss: a foreign miss is the expected
    // steady state on a busy gateway, while this one means null dpps or a broken
    // descriptor -- completely different diagnoses that must not share a number.
    assert!(seed.contains("RGWTRACE_DIAG_OPERATE_UNRESOLVED_CTX_CLEARED"));
    assert!(seed.contains("RGWTRACE_DIAG_OPERATE_MISS_CTX_CLEARED"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_OPERATE_UNRESOLVED_CTX_CLEARED = 27,"));
}

#[test]
fn the_bridge_is_multi_keyed_by_req_state_and_rgw_op() {
    // WITHOUT THIS, PHASE B RECOVERS NOTHING. RGW threads a
    // `const DoutPrefixProvider* dpp` down its data path, and at most call sites
    // inside an op's execute() that pointer is the RGWOp (`this`), NOT the
    // req_state. A bridge keyed only on req_state* would MISS on the entire op data
    // path -- every lookup a foreign-dpp miss, every counter healthy, zero ops
    // recovered.
    //
    // So a request is inserted under BOTH identities. The RGWOp* is read at
    // rgw_process_authenticated from the `RGWOp*& op` parameter (slot 41): a
    // REFERENCE to a pointer, so the register holds an RGWOp** and exactly ONE read
    // of the pointee yields the RGWOp*.
    assert!(RGWTRACE_BPF.contains("int varid_op = 41;"));
    assert!(RGWTRACE_BPF.contains("    op_ptr = fetch_param_ptr_ref(ctx, op_vf);"));
    assert!(BPF_UTILS.contains(
        "static __always_inline __u64 fetch_param_ptr_ref(const struct pt_regs *const ctx,"
    ));
    // Both keys map to the same value, built by the same key constructor.
    assert!(RGWTRACE_BPF.contains("struct reqstate_key okey = make_reqstate_key(op_ptr, tgid);"));
    assert!(RGWTRACE_BPF.contains(
        "if (bpf_map_update_elem(&rgw_ctx_by_reqstate, &okey, &ctx_copy, BPF_ANY) != 0) {"
    ));
    // The alternate key is stored INSIDE the context value, which is what lets a
    // seed report WHICH key it hit on (the measurement that decides the key's fate).
    assert!(RGWTRACE_BPF.contains("__u64 rgw_op_ptr;"));
    assert!(RGWTRACE_BPF.contains("      ctx_copy.rgw_op_ptr = op_ptr;"));
    // An unrevocable key is never created: no canonical req_state* => no alt key.
    assert!(RGWTRACE_BPF.contains("} else if (op_ptr != 0 && ctx_copy.req_state_ptr != 0) {"));
}

#[test]
fn the_destructor_revokes_every_key_the_request_was_inserted_under() {
    // A KEY THAT OUTLIVES ITS REQUEST IS A MIS-CORRELATION SOURCE: RGWOp is
    // heap-allocated and its address is recycled, so a stale alternate key can be
    // hit by a later, unrelated dpp and seed a DEAD request's trans_id.
    //
    // The destructor therefore deletes the alternate key as well as the canonical
    // one -- but only while the alternate entry still describes THIS request. A
    // NEWER request may already have re-keyed that recycled address to itself
    // (BPF_ANY overwrite at its own rgw_process_authenticated, which always precedes
    // any op it submits); deleting then would revoke a LIVE request's key.
    let dtor = probe_body("int uprobe_rgw_req_state_dtor(struct pt_regs *ctx) {");
    assert!(dtor.contains("bpf_map_delete_elem(&rgw_ctx_by_reqstate, &rkey);"));
    assert!(dtor.contains("struct reqstate_key okey = make_reqstate_key(op_ptr, tgid);"));
    assert!(dtor.contains(concat!(
        "    } else if (alt->start_ns == start_ns && alt->tid == owner_tid &&\n",
        "               alt->pid == tgid) {\n",
        "      bpf_map_delete_elem(&rgw_ctx_by_reqstate, &okey);\n",
        "      count_diag(RGWTRACE_DIAG_RGWOP_KEY_REVOKES);\n",
        "    } else {\n",
        "      count_diag(RGWTRACE_DIAG_RGWOP_KEY_REVOKE_SKIPPED);"
    )));
}

#[test]
fn revocation_is_total_and_survives_an_lru_eviction_of_the_canonical_entry() {
    // FINDING (the invariant was FALSE): the alternate key used to be recovered at
    // the destructor from the CANONICAL BRIDGE VALUE -- which lives in an LRU. Evict
    // just the canonical entry (LRU eviction is per-entry, not per-request) and the
    // destructor's lookup misses, it RETURNS EARLY, and the alternate key it never
    // learned about is stranded forever. The documented "every inserted key is
    // revoked" invariant and the `inserts - revokes` health metric were therefore
    // both false as written.
    //
    // Revocation is now driven by `rgw_op_keys`: a PLAIN HASH (never evicts) keyed
    // by the canonical key, written BEFORE the alternate key is inserted, and read
    // by the destructor UNCONDITIONALLY -- including on a canonical miss.
    assert!(RGWTRACE_BPF.contains(concat!(
        "  __uint(type, BPF_MAP_TYPE_HASH);\n",
        "  __type(key, struct reqstate_key);\n",
        "  __type(value, struct rgw_op_key_record);\n",
        "  __uint(max_entries, 16384);\n",
        "} rgw_op_keys SEC(\".maps\");"
    )));
    // NOT an LRU: an evicting revocation index would reintroduce the exact bug.
    assert!(!RGWTRACE_BPF.contains(concat!(
        "  __uint(type, BPF_MAP_TYPE_LRU_HASH);\n",
        "  __type(key, struct reqstate_key);\n",
        "  __type(value, struct rgw_op_key_record);\n",
    )));

    // The record is written BEFORE the alternate key is inserted, and a failure to
    // write it means the alternate key is NOT inserted at all (fail closed: never
    // create a key nobody can revoke).
    let authed = probe_body("int uprobe_rgw_process_authenticated(struct pt_regs *ctx) {");
    let record_write = authed
        .find("if (bpf_map_update_elem(&rgw_op_keys, &rkey, &record, BPF_ANY) != 0) {")
        .expect("record write");
    let alt_insert = authed
        .find("struct reqstate_key okey = make_reqstate_key(op_ptr, tgid);")
        .expect("alternate key insert");
    assert!(
        record_write < alt_insert,
        "the revocation record must exist before the key it revokes"
    );
    assert!(authed.contains("count_diag(RGWTRACE_DIAG_RGWOP_KEY_INDEX_DROPS);"));
    // ...and a failed alternate insert deletes the record again, so a record can
    // never name a key that does not exist.
    assert!(authed.contains("        bpf_map_delete_elem(&rgw_op_keys, &rkey);"));

    // The destructor consults the record even when the canonical entry is GONE: the
    // canonical miss counts and falls through, it does not return.
    let dtor = probe_body("int uprobe_rgw_req_state_dtor(struct pt_regs *ctx) {");
    let miss = dtor
        .find("count_diag(RGWTRACE_DIAG_REQUEST_END_MISSES);")
        .expect("canonical miss");
    let record_read = dtor
        .find("bpf_map_lookup_elem(&rgw_op_keys, &rkey);")
        .expect("record read");
    assert!(
        miss < record_read,
        "a canonical-entry miss must NOT skip the alternate-key revocation"
    );
    // The ONLY early returns before the revocation are the two that cannot possibly
    // have a record to revoke: a missing `this` descriptor, and an unresolvable
    // `this` pointer. The record is keyed by that very pointer, so without it there
    // is nothing to look up. Every other path -- crucially the canonical-entry miss
    // -- must fall through to the revocation.
    assert_eq!(
        dtor[..record_read].matches("return 0;").count(),
        2,
        "only an absent/unresolvable `this` may return before the revocation"
    );
    // An alternate key already gone from the bridge (LRU-evicted) is accounted for
    // too, so INSERTS == REVOKES + SKIPPED + ABSENT + in-flight holds exactly.
    assert!(dtor.contains("count_diag(RGWTRACE_DIAG_RGWOP_KEY_REVOKE_ABSENT);"));
}

#[test]
fn phase_b_is_not_attached_without_the_request_end_probe() {
    // The per-submit re-seed looks EVERY rados operate's dpp up in the bridge. That
    // is only safe while bridge entries are REVOKED at request end -- which only the
    // END probe does. Without it, entries live forever, a recycled req_state stack
    // address or RGWOp heap address HITS a long-dead request's entry, and its
    // trans_id is seeded onto a live submit. The liveness gate cannot save us there
    // either: with no revoker it is switched off and fails OPEN.
    //
    // So Phase B degrades to Phase A -- loudly.
    assert!(LIVE_LINUX.contains(concat!(
        "                    if request_end_probe {\n",
        "                        attach_rados_operate_probes(&mut links, skel, dwarf, &targets.radosgw, pid);\n",
        "                    } else {\n",
    )));
    assert!(LIVE_LINUX.contains(
        "the per-submit re-seed (rgw_rados_operate) \\\n                             is DISABLED \
         because the request-END probe did not attach."
    ));
}

#[test]
fn both_rados_operate_overloads_are_probed_from_distinct_hprobe_slots() {
    // rgw_rados_operate has TWO overloads (ObjectReadOperation /
    // ObjectWriteOperation) at two addresses. Probing only one silently loses an
    // entire half of the data path. Each gets its own program and its own hprobe
    // slot, so each address is only ever read with the descriptor extracted from
    // that same definition -- the two are EXPECTED to agree (dpp is arg0 in both),
    // but nothing here relies on that.
    assert!(RGWTRACE_BPF.contains("int uprobe_rgw_rados_operate_read(struct pt_regs *ctx)"));
    assert!(RGWTRACE_BPF.contains("int uprobe_rgw_rados_operate_write(struct pt_regs *ctx)"));
    assert!(RGWTRACE_BPF.contains("return rgw_rados_operate_seed(ctx, 60);"));
    assert!(RGWTRACE_BPF.contains("return rgw_rados_operate_seed(ctx, 70);"));

    // Both are attached, each by its own provenance-checked address.
    assert!(LIVE_LINUX.contains("&skel.progs.uprobe_rgw_rados_operate_read"));
    assert!(LIVE_LINUX.contains("&skel.progs.uprobe_rgw_rados_operate_write"));
    // The addresses come from the provenance-checked accessor, never from the
    // generic `function_addr` path (which cannot tell the overloads apart).
    assert!(LIVE_LINUX.contains("dwarf.rados_operate_probe(&module, function)"));
}

#[test]
fn rados_operate_seed_wires_coverage_counters() {
    assert!(RGWTRACE_BPF.contains("count_diag(RGWTRACE_DIAG_OPERATE_SEED_HITS)"));
    assert!(RGWTRACE_BPF.contains("count_diag(RGWTRACE_DIAG_OPERATE_SEED_MISSES)"));
    assert!(RGWTRACE_BPF.contains("count_diag(RGWTRACE_DIAG_OPERATE_BASE_UNRESOLVED)"));
    // ABI mirror: appended after the existing counters, which keep their slots.
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_OPERATE_SEED_HITS = 15,"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_OPERATE_SEED_MISSES = 16,"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_OPERATE_BASE_UNRESOLVED = 17,"));
}

#[test]
fn rados_operate_probe_attach_fails_soft_and_is_never_silent() {
    // An older/stripped RGW whose rgw_rados_operate symbols cannot be resolved
    // must keep tracing -- degrading to Phase A behavior -- rather than failing the
    // run. But it must never degrade SILENTLY: without this probe most request ops
    // are reported as background ops, which looks like a broken gateway rather
    // than a missing probe.
    assert!(LIVE_LINUX.contains("fn attach_rados_operate_probes("));
    assert!(LIVE_LINUX.contains("RadosOperateProbe::Unavailable(gap) => {"));
    assert!(LIVE_LINUX.contains("NEITHER rgw_rados_operate overload could be probed"));
    // Fail-soft: the per-overload attach returns an outcome, it does not `?`.
    assert!(LIVE_LINUX.contains("fn attach_rados_operate_probe(\n    links: &mut Vec<Link>,"));
}

/// The body of the Phase B seed handler, isolated so the "never dereference the
/// dpp" and "fail closed on a miss" invariants are asserted about THAT function
/// rather than about the whole BPF source (where `bpf_probe_read_user` and
/// `bpf_map_delete_elem` legitimately appear in other probes).
fn phase_b_seed_body() -> &'static str {
    let start = RGWTRACE_BPF
        .find("static __always_inline int rgw_rados_operate_seed(")
        .expect("phase B seed handler");
    let rest = &RGWTRACE_BPF[start..];
    let end = rest
        .find("\nSEC(\"uprobe\")")
        .expect("phase B seed handler is followed by its uprobe stubs");
    &rest[..end]
}

/// The body of one BPF probe, from its signature to the closing brace of the
/// function (the next line that starts a new top-level construct).
fn probe_body(signature: &str) -> &'static str {
    let start = RGWTRACE_BPF
        .find(signature)
        .unwrap_or_else(|| panic!("probe not found: {signature}"));
    let rest = &RGWTRACE_BPF[start..];
    let end = rest.find("\n}\n").expect("probe has a closing brace");
    &rest[..end]
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
