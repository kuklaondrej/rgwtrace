const RGWTRACE_BPF: &str = include_str!("../bpf/rgwtrace.bpf.c");
const RGWTRACE_EVENTS: &str = include_str!("../bpf/rgwtrace_events.h");
const BPF_UTILS: &str = include_str!("../bpf/bpf_utils.h");
const DWARF_NATIVE: &str = include_str!("../src/dwarf_native.rs");
const LIVE_LINUX: &str = include_str!("../src/live/linux.rs");

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
fn varfield_member_addr_uses_fixed_field_offsets() {
    assert!(BPF_UTILS.contains("static __noinline __u64 fetch_var_member_addr"));
    assert!(BPF_UTILS.contains("static __noinline __u64 fetch_var_value"));
    assert!(BPF_UTILS.contains("int raw_size = vf->size;"));
    assert!(BPF_UTILS.contains("if (raw_size > 0)"));
    assert!(BPF_UTILS.contains("if (size > 10)"));
    assert!(BPF_UTILS.contains("#define RGWTRACE_APPLY_VAR_FIELD(IDX)"));
    assert!(BPF_UTILS.contains("vf->fields[IDX].offset"));
    assert!(!BPF_UTILS.contains("for (int i = 2; i < 10; i++)"));
    assert!(!BPF_UTILS.contains("vf->fields[i]"));

    for idx in 2..=9 {
        assert!(BPF_UTILS.contains(&format!("RGWTRACE_APPLY_VAR_FIELD({idx})")));
    }
}

#[test]
fn varfield_accessors_are_bpf_subprograms() {
    assert!(RGWTRACE_BPF.contains("static __noinline __u64 direct_var_value"));
    assert!(RGWTRACE_BPF.contains("static __noinline __u64 pointer_member_value"));
    assert!(RGWTRACE_BPF.contains("static __noinline __u64 member_address"));
}

#[test]
fn bpf_records_rados_sender_thread_id() {
    assert!(RGWTRACE_EVENTS.contains("__u32 send_tid;"));
    assert!(RGWTRACE_BPF.contains("__u32 thread_id = get_tid();"));
    assert!(RGWTRACE_BPF.contains("event->send_tid = thread_id;"));
}

#[test]
fn bpf_propagates_rgw_context_to_objecter_ops() {
    assert!(RGWTRACE_EVENTS.contains("char rgw_req_id[MAX_RGW_REQ_ID];"));
    assert!(RGWTRACE_EVENTS.contains("__u64 rgw_request_id;"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_CORRELATION_OP_SUBMIT_CONTEXT"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_PUT_PROCESSOR_PREPARE_HITS"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_PUT_PROCESSOR_PREPARE_CONTEXTS"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_HEAD_OBJECT_PROCESSOR_PROCESS_HITS"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_HEAD_OBJECT_PROCESSOR_PROCESS_CONTEXTS"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_RGW_WRITE_META_HITS"));
    assert!(RGWTRACE_EVENTS.contains("RGWTRACE_DIAG_RGW_WRITE_META_CONTEXTS"));
    assert!(RGWTRACE_BPF.contains("__uint(type, BPF_MAP_TYPE_LRU_HASH);"));
    assert!(RGWTRACE_BPF.contains("} rgw_req_states SEC(\".maps\");"));
    assert!(RGWTRACE_BPF.contains("} rgw_ops SEC(\".maps\");"));
    assert!(RGWTRACE_BPF.contains("} rados_writers SEC(\".maps\");"));
    assert!(RGWTRACE_BPF.contains("} rgw_rados_objs SEC(\".maps\");"));
    assert!(RGWTRACE_BPF.contains("} objecter_ops SEC(\".maps\");"));
    assert!(RGWTRACE_BPF.contains("} pending_data_processors SEC(\".maps\");"));
    assert!(RGWTRACE_BPF.contains("} pending_stripe_objs SEC(\".maps\");"));
    assert!(RGWTRACE_BPF.contains("int uprobe_process_request"));
    assert!(RGWTRACE_BPF.contains("int uprobe_rgw_op_init"));
    assert!(RGWTRACE_BPF.contains("int uprobe_rados_writer_ctor"));
    assert!(RGWTRACE_BPF.contains("int uprobe_manifest_processor_ctor"));
    assert!(RGWTRACE_BPF.contains("int uprobe_rados_writer_set_stripe_obj"));
    assert!(RGWTRACE_BPF.contains("int uretprobe_rados_writer_set_stripe_obj"));
    assert!(RGWTRACE_BPF.contains("int uprobe_rgw_rados_obj_aio_operate"));
    assert!(RGWTRACE_BPF.contains("int uprobe_rgw_rados_obj_operate"));
    assert!(RGWTRACE_BPF.contains("int uprobe_aio_get"));
    assert!(RGWTRACE_BPF.contains("int uprobe_librados_operate"));
    assert!(RGWTRACE_BPF.contains("int uprobe_put_processor_prepare"));
    assert!(RGWTRACE_BPF.contains("int uprobe_put_processor_process_first_chunk"));
    assert!(RGWTRACE_BPF.contains("int uretprobe_put_processor_process_first_chunk"));
    assert!(RGWTRACE_BPF.contains("int uprobe_head_object_processor_process"));
    assert!(RGWTRACE_BPF.contains("int uretprobe_head_object_processor_process"));
    assert!(RGWTRACE_BPF.contains("count_diag(RGWTRACE_DIAG_HEAD_OBJECT_PROCESSOR_PROCESS_HITS)"));
    assert!(
        RGWTRACE_BPF.contains("count_diag(RGWTRACE_DIAG_HEAD_OBJECT_PROCESSOR_PROCESS_CONTEXTS)")
    );
    assert!(RGWTRACE_BPF.contains("int uprobe_objecter_op_submit"));
    assert!(RGWTRACE_BPF.contains("request->flags = 0;"));
    assert!(RGWTRACE_BPF.contains("__u64 value_len = 0;"));
    assert!(RGWTRACE_BPF
        .contains("__builtin_memset(request->rgw_req_id, 0, sizeof(request->rgw_req_id));"));
    assert!(
        RGWTRACE_BPF.contains("__builtin_memset(request->trans_id, 0, sizeof(request->trans_id));")
    );
    assert!(RGWTRACE_BPF
        .contains("struct rgw_request_ctx *request = bpf_map_lookup_elem(&rgw_ops, &dpp);"));
    assert!(RGWTRACE_BPF.contains("request = bpf_map_lookup_elem(&rgw_req_states, &dpp);"));
    assert!(RGWTRACE_BPF.contains("request = bpf_map_lookup_elem(&rgw_dpps, &dpp);"));
    assert!(RGWTRACE_BPF.contains("prefer_newer_current_thread_request(request)"));
    assert!(RGWTRACE_BPF.contains("lookup_current_thread_request(void)"));
    assert!(RGWTRACE_BPF.contains("push_current_request_ctx_no_clear(void)"));
    assert!(RGWTRACE_BPF.contains("bpf_map_update_elem(&rados_writers, &writer, request, 0)"));
    assert!(RGWTRACE_BPF.contains("bpf_map_lookup_elem(&rgw_aios, &aio)"));
    assert!(RGWTRACE_BPF.contains("return lookup_request_ctx_for_dpp(aio);"));
    assert!(RGWTRACE_BPF.contains("if (writer != 0 &&"));
    assert!(RGWTRACE_BPF.contains("push_context_for_writer_no_clear(writer)"));
    assert!(RGWTRACE_BPF.contains("request = lookup_current_thread_request();"));
    assert!(RGWTRACE_BPF.contains("#define RGWTRACE_RADOS_WRITER_AIO_OFFSET 0x08"));
    assert!(RGWTRACE_BPF.contains("#define RGWTRACE_RADOS_WRITER_DPP_OFFSET 0x2f8"));
    assert!(RGWTRACE_BPF.contains("#define RGWTRACE_RADOS_WRITER_CTOR_SLOT_OFFSET 0x1a8"));
    assert!(RGWTRACE_BPF.contains("#define RGWTRACE_PIPE_NEXT_OFFSET 0x08"));
    assert!(RGWTRACE_BPF.contains("#define RGWTRACE_HEAD_PROCESSOR_PROCESSOR_OFFSET 0x30"));
    assert!(RGWTRACE_BPF.contains("#define RGWTRACE_PUT_PROCESSOR_WRITER_OFFSET 0x2c8"));
    assert!(RGWTRACE_BPF.contains("#define RGWTRACE_MANIFEST_PROCESSOR_DPP_OFFSET 0xf70"));
    assert!(RGWTRACE_BPF.contains("cache_writer_from_active_context(writer)"));
    assert!(
        RGWTRACE_BPF.contains("lookup_request_ctx_for_processor_or_dpp(processor, pending->dpp)")
    );
    assert!(
        RGWTRACE_BPF.contains("cache_data_processor_chain_for_request(data_processor, request)")
    );
    assert!(RGWTRACE_BPF.contains("RGWTRACE_HEAD_PROCESSOR_PROCESSOR_OFFSET"));
    assert!(RGWTRACE_BPF.contains("processor + RGWTRACE_PIPE_NEXT_OFFSET"));
    assert!(RGWTRACE_BPF.contains("next + RGWTRACE_PIPE_NEXT_OFFSET"));
    assert!(RGWTRACE_BPF.contains("processor + RGWTRACE_PUT_PROCESSOR_WRITER_OFFSET"));
    assert!(RGWTRACE_BPF.contains(
        "processor +\n                                    RGWTRACE_MANIFEST_PROCESSOR_DPP_OFFSET"
    ));
    assert!(RGWTRACE_BPF.contains("writer - RGWTRACE_PUT_PROCESSOR_WRITER_OFFSET"));
    assert!(!RGWTRACE_BPF.contains("request = lookup_request_ctx_for_writer_aio(writer);"));
    assert!(RGWTRACE_BPF.contains("bpf_map_update_elem(&rados_writers, &processor, request, 0)"));
    assert!(RGWTRACE_BPF.contains("bpf_map_update_elem(&rgw_dpps, &dpp, request, 0)"));
    assert!(RGWTRACE_BPF.contains("bpf_map_update_elem(&rgw_aios, &aio, request, 0)"));
    assert!(RGWTRACE_BPF.contains("aio + RGWTRACE_RADOS_WRITER_CTOR_SLOT_OFFSET"));
    assert!(RGWTRACE_BPF.contains("direct_var_value(ctx, 102)"));
    assert!(RGWTRACE_BPF.contains("direct_var_value(ctx, 200)"));
    assert!(RGWTRACE_BPF.contains("direct_var_value(ctx, 201)"));
    assert!(RGWTRACE_BPF.contains("direct_var_value(ctx, 202)"));
    assert!(RGWTRACE_BPF.contains("direct_var_value(ctx, 210)"));
    assert!(RGWTRACE_BPF.contains("member_address(ctx, 211)"));
    assert!(RGWTRACE_BPF.contains("direct_var_value(ctx, 220)"));
    assert!(RGWTRACE_BPF.contains("direct_var_value(ctx, 221)"));
    assert!(RGWTRACE_BPF.contains("direct_var_value(ctx, 240)"));
    assert!(RGWTRACE_BPF.contains("direct_var_value(ctx, 241)"));
    assert!(
        RGWTRACE_BPF.contains("push_context_for_rados_obj_no_clear(direct_var_value(ctx, 230))")
    );
    assert!(
        RGWTRACE_BPF.contains("push_context_for_rados_obj_no_clear(direct_var_value(ctx, 231))")
    );
    assert!(RGWTRACE_BPF.contains("cache_manifest_processor_ctor_context(processor, dpp, aio)"));
    assert!(RGWTRACE_BPF.contains("cache_processor_context(ctx, 110, 111, 112)"));
    assert!(RGWTRACE_BPF.contains("cache_processor_context(ctx, 114, 115, 116)"));
    assert!(RGWTRACE_BPF.contains("cache_processor_context(ctx, 117, 118, 119)"));
    assert!(RGWTRACE_BPF.contains("cache_data_processor_output(ctx, 120, 121, 122, 123)"));
    assert!(RGWTRACE_BPF.contains("cache_data_processor_output(ctx, 130, 131, 132, 133)"));
    assert!(RGWTRACE_BPF.contains("cache_data_processor_output(ctx, 140, 141, 142, 143)"));
    assert!(RGWTRACE_BPF.contains("__u64 writer = member_address(ctx, writer_varid);"));
    assert!(RGWTRACE_BPF.contains("__u64 dpp = pointer_member_value(ctx, dpp_varid);"));
    assert!(RGWTRACE_BPF.contains("int uprobe_put_processor_complete"));
    assert!(RGWTRACE_BPF.contains("int uprobe_rgw_write_meta"));
    assert!(RGWTRACE_BPF.contains("cache_processor_context(ctx, 160, 161, 162)"));
    assert!(RGWTRACE_BPF.contains("cache_processor_context(ctx, 170, 171, 172)"));
    assert!(RGWTRACE_BPF.contains("cache_processor_context(ctx, 180, 181, 182)"));
    assert!(RGWTRACE_BPF.contains("push_context_for_dpp_no_clear(direct_var_value(ctx, 190))"));
    assert!(RGWTRACE_BPF.contains("push_context_for_dpp_no_clear(direct_var_value(ctx, 191))"));
    assert!(RGWTRACE_BPF.contains("copy_current_active_request_ctx(&active, false)"));
    assert!(RGWTRACE_BPF.contains("__u64 dpp = pointer_member_value(ctx, 71);"));
    assert!(RGWTRACE_BPF.contains("__u64 dpp = pointer_member_value(ctx, 81);"));
    assert!(RGWTRACE_BPF.contains("__u64 writer = fetch_register(ctx, RGWTRACE_ABI_THIS_REG);"));
    assert!(RGWTRACE_BPF.contains("rgwtrace_probe_read_user(&processor, sizeof(processor),"));
    assert!(RGWTRACE_BPF.contains("bpf_map_update_elem(&rgw_rados_objs, &pending->stripe_obj"));
    assert!(RGWTRACE_BPF.contains("count_diag(RGWTRACE_DIAG_PUT_PROCESSOR_PREPARE_HITS)"));
    assert!(RGWTRACE_BPF.contains("count_diag(RGWTRACE_DIAG_PUT_PROCESSOR_PREPARE_CONTEXTS)"));
    assert!(LIVE_LINUX.contains("\"AtomicObjectProcessor::prepare\""));
    assert!(LIVE_LINUX.contains("\"MultipartObjectProcessor::prepare\""));
    assert!(LIVE_LINUX.contains("\"AppendObjectProcessor::prepare\""));
    assert!(LIVE_LINUX.contains("\"AtomicObjectProcessor::process_first_chunk\""));
    assert!(LIVE_LINUX.contains("\"MultipartObjectProcessor::process_first_chunk\""));
    assert!(LIVE_LINUX.contains("\"AppendObjectProcessor::process_first_chunk\""));
    assert!(LIVE_LINUX.contains("\"HeadObjectProcessor::process\""));
    assert!(LIVE_LINUX.contains("\"ManifestObjectProcessor::ManifestObjectProcessor\""));
    assert!(LIVE_LINUX.contains("\"AtomicObjectProcessor::complete\""));
    assert!(LIVE_LINUX.contains("\"MultipartObjectProcessor::complete\""));
    assert!(LIVE_LINUX.contains("\"AppendObjectProcessor::complete\""));
    assert!(LIVE_LINUX.contains("\"RGWRados::Object::Write::write_meta\""));
    assert!(LIVE_LINUX.contains("\"RGWRados::Object::Write::_do_write_meta\""));
    assert!(LIVE_LINUX.contains("\"RadosWriter::set_stripe_obj\""));
    assert!(LIVE_LINUX.contains("\"RGWSI_RADOS::Obj::aio_operate\""));
    assert!(LIVE_LINUX.contains("\"RGWSI_RADOS::Obj::operate\""));
    assert!(LIVE_LINUX.contains("\"librados::v14_2_0::IoCtx::operate\""));
    assert!(LIVE_LINUX.contains("\"librados::v14_2_0::IoCtx::aio_operate\""));
    assert!(LIVE_LINUX.contains("\"BlockingAioThrottle::get\""));
    assert!(LIVE_LINUX.contains("\"YieldingAioThrottle::get\""));
    assert!(LIVE_LINUX.contains("uprobe_put_processor_process_first_chunk"));
    assert!(LIVE_LINUX.contains("uprobe_put_processor_complete"));
    assert!(LIVE_LINUX.contains("uprobe_rgw_write_meta"));
    assert!(LIVE_LINUX.contains("uprobe_head_object_processor_process"));
    assert!(LIVE_LINUX.contains("uprobe_manifest_processor_ctor"));
    assert!(LIVE_LINUX.contains("uprobe_rados_writer_set_stripe_obj"));
    assert!(LIVE_LINUX.contains("uretprobe_rados_writer_set_stripe_obj"));
    assert!(LIVE_LINUX.contains("uprobe_rgw_rados_obj_aio_operate"));
    assert!(LIVE_LINUX.contains("uprobe_rgw_rados_obj_operate"));
    assert!(LIVE_LINUX.contains("uprobe_librados_operate"));
    assert!(LIVE_LINUX.contains("uprobe_aio_get"));
    assert!(!LIVE_LINUX.contains("uretprobe_put_processor_process_first_chunk"));
    assert!(!LIVE_LINUX.contains("uretprobe_head_object_processor_process"));
    assert!(RGWTRACE_BPF.contains("RGWTRACE_CORRELATION_OP_SUBMIT_CONTEXT"));
    assert!(RGWTRACE_BPF.contains("RGWTRACE_CORRELATION_ACTIVE_CONTEXT"));
    assert!(RGWTRACE_BPF.contains("RGWTRACE_CORRELATION_SAME_THREAD"));
    assert!(RGWTRACE_BPF.contains("#define RGWTRACE_ACTIVE_CTX_TTL_NS"));
    assert!(RGWTRACE_BPF.contains("const volatile bool RGWTRACE_ATTACH_SCOPED_RETURN_PROBES"));
    assert!(RGWTRACE_BPF.contains("if (!RGWTRACE_ATTACH_SCOPED_RETURN_PROBES)"));
    assert!(RGWTRACE_BPF.contains("for (int i = RGWTRACE_ACTIVE_CTX_DEPTH - 1; i >= 0; --i)"));
    assert!(RGWTRACE_BPF.contains("if (stack->depth > i)"));
    assert!(RGWTRACE_BPF.contains("if (stack->frames[i].valid)"));
    assert!(RGWTRACE_BPF.contains("push_context_for_dpp_no_clear(direct_var_value(ctx, 61))"));
    assert!(RGWTRACE_BPF.contains("clear_active_request_ctx();"));
    assert!(RGWTRACE_BPF.contains("struct objecter_op_ctx"));
    assert!(RGWTRACE_BPF.contains("copy_current_active_request_ctx(&op_ctx.request, false)"));
    assert!(
        RGWTRACE_BPF.contains("struct rgw_request_ctx *request = lookup_current_thread_request();")
    );
    assert!(RGWTRACE_BPF.contains("op_ctx.source = RGWTRACE_CORRELATION_SAME_THREAD;"));
    assert!(
        RGWTRACE_BPF.contains("copy_request_ctx_to_rados_event(event, request, op_ctx->source);")
    );
    assert!(RGWTRACE_BPF.contains("copy_current_active_request_ctx(&active_request, false)"));
    assert!(RGWTRACE_BPF.contains("count_diag(RGWTRACE_DIAG_RADOS_FINISH_MISSES);\n    if (objecter_op != 0)\n      bpf_map_delete_elem(&objecter_ops, &objecter_op);"));
    assert!(RGWTRACE_BPF.contains("count_diag(RGWTRACE_DIAG_RINGBUF_RADOS_DROPS);\n    bpf_map_delete_elem(&rados_ops, &key);\n    if (objecter_op != 0)\n      bpf_map_delete_elem(&objecter_ops, &objecter_op);"));
}

#[test]
fn process_request_has_no_return_probe() {
    assert!(RGWTRACE_BPF.contains("int uprobe_process_request"));
    assert!(!RGWTRACE_BPF.contains("uretprobe_process_request"));
}

#[test]
fn live_attach_scoped_return_probes_are_opt_in() {
    assert!(RGWTRACE_BPF.contains("int uretprobe_rgw_rados_scope"));
    assert!(LIVE_LINUX.contains("attach_scoped_return_probes: bool"));
    assert!(LIVE_LINUX
        .contains("rodata.RGWTRACE_ATTACH_SCOPED_RETURN_PROBES = attach_scoped_return_probes;"));
    assert!(LIVE_LINUX.contains("if attach_scoped_return_probes"));
    assert!(LIVE_LINUX.contains("skel.progs.uretprobe_rgw_rados_scope"));
    assert!(LIVE_LINUX.contains("\"rgw_rados_operate\""));
    assert!(LIVE_LINUX.contains("\"RadosWriter::process\""));
    assert!(LIVE_LINUX.contains("\"RadosWriter::write_exclusive\""));
    assert!(!RGWTRACE_BPF.contains("uretprobe_process_request"));
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
