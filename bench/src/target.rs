// SPDX-License-Identifier: GPL-2.0-only
//! The synthetic target: `#[no_mangle] extern "C"` functions whose register /
//! memory layout satisfies each real rgwtrace probe's descriptor, plus the
//! backing data those functions point at and the `hprobes` descriptor set that
//! makes each real program run its FULL body.
//!
//! We uprobe THIS binary (`/proc/self/exe`) at these symbols, so no Ceph is
//! needed. Each function takes a pointer to a synthetic struct in its first
//! argument register; the matching descriptor tells the BPF program which
//! member to read, exactly as a real Ceph descriptor would.

use std::ffi::c_void;

use crate::descriptors::{raw_pointer, reg_member, VarFieldK, ARG0_REG};

/// Ceph `CEPH_OSD_OP_READ` (`RD|DATA|1`). An extent op, so send_op's ops loop
/// takes the `ceph_osd_op_extent` branch and reads offset/length -- the fuller,
/// more representative path.
pub const SYN_OSD_OP_READ: u16 = 0x1000 | 0x0200 | 1;

// Synthetic scalar values, chosen distinct and nonzero so a full-path event can
// be verified field-by-field: a zero where one of these is expected proves the
// program bailed before writing that field.
pub const SYN_TID: u64 = 0x1111_2222_3333_4444;
pub const SYN_CID: u64 = 0x5555_6666_7777_8888;
pub const SYN_TARGET_OSD: u32 = 7;
pub const SYN_POOL: u64 = 42;
pub const SYN_PG_SEED: u32 = 123;
pub const SYN_NAME_LEN: i32 = 5;
pub const SYN_OPS_SIZE: u32 = 1;
pub const SYN_OBJECT_NAME: &[u8] = b"bench";
/// The trans_id string get_handler reads and send_op stamps onto a correlated
/// op. Verified in the combined phase to prove the liveness-gate/stamp path ran.
pub const SYN_TRANS_ID: &[u8] = b"bench-trans-id";
/// The three acting-OSD ids. ALL nonzero and distinct so a failed
/// `bpf_probe_read_user` of the acting array (which would leave the field at its
/// -1 init) is distinguishable from a successful read.
pub const SYN_ACTING: [i32; 3] = [111, 222, 333];
/// The extent op's offset/length. Nonzero sentinels: send_op only writes these
/// (from ops_start+6 / +14) on the extent branch, and a zero here used to be
/// indistinguishable from a failed read.
pub const SYN_EXTENT_OFFSET: u64 = 0xDEAD_BEEF_0000_1111;
pub const SYN_EXTENT_LENGTH: u64 = 0x0000_2222_CAFE_F00D;

/// Mirror of the request-side pointer argument. `RGWREST::get_handler`'s slot-30
/// descriptor reads an `int` (trans_id length) and slot-31 reads a pointer (the
/// trans_id string base), both as members off the argument register. The
/// argument value itself is the request's `req_state*` bridge key.
#[repr(C)]
pub struct ReqState {
    /// slot 30: `trans_id_len` -- must be `> 0` for get_handler to emit a START.
    pub trans_id_len: i32,
    pub _pad: i32,
    /// slot 31: pointer to a NUL-terminated trans_id string -- must be `> 0`.
    pub trans_id_ptr: u64,
}

/// Mirror of the RADOS-submit pointer argument. Every send_op slot (0..=11) and
/// finish_op slot (20,21) reads one member of this struct off the argument
/// register. Pointer members (`name_ptr`, `acting_*`, `ops_start`) hold
/// addresses of the backing buffers below; the program dereferences them.
#[repr(C)]
pub struct SynOp {
    pub tid: u64,           // slot 0 / 20  (client_op_key.tid)
    pub cid: u64,           // slot 1 / 21  (client_op_key.cid)
    pub target_osd: u32,    // slot 2
    pub name_len: i32,      // slot 3
    pub name_ptr: u64,      // slot 4  -> object name string
    pub rw: u16,            // slot 5
    pub pool: u64,          // slot 6
    pub pg_seed: u32,       // slot 7
    pub acting_start: u64,  // slot 8  -> &acting[0]
    pub acting_finish: u64, // slot 9  -> &acting[3] (one past end; (finish-start)=12=3*int)
    pub ops_start: u64,     // slot 10 -> ops buffer
    pub ops_size: u32,      // slot 11
}

/// Owns the backing memory and hands out stable pointers. Boxed buffers are
/// never moved for the lifetime of this value, so the raw pointers stored inside
/// `req_state`/`syn_op` stay valid for the whole run.
pub struct SynState {
    pub req_state: Box<ReqState>,
    pub syn_op: Box<SynOp>,
    // Kept alive; pointed at by the structs above.
    _trans_id: Box<[u8]>,
    _object_name: Box<[u8]>,
    _acting: Box<[i32]>,
    _ops_buf: Box<[u8]>,
}

impl SynState {
    pub fn new() -> Self {
        // trans_id: a NUL-terminated string for get_handler's str read.
        let mut trans_id = SYN_TRANS_ID.to_vec();
        trans_id.push(0);
        let trans_id = trans_id.into_boxed_slice();

        // object name: NOT NUL-terminated read (send_op reads name_len bytes),
        // but give it slack anyway.
        let object_name = SYN_OBJECT_NAME.to_vec().into_boxed_slice();

        // acting: three ints so acting_finish-acting_start == 12 == 3*sizeof(int).
        // All nonzero + distinct (see SYN_ACTING) so a failed read is visible.
        let acting: Box<[i32]> = SYN_ACTING.to_vec().into_boxed_slice();

        // ops buffer: one op. 112 bytes is Ceph squid's CEPH_OSD_OP_SIZE, and it
        // is large enough for the extent reads at +6 and +14. Layout matches what
        // send_op reads: ops[0] code (u16) at offset 0, the extent offset (u64) at
        // CEPH_OSD_OP_EXTENT_OFFSET_OFFSET=6, the extent length (u64) at
        // CEPH_OSD_OP_EXTENT_LENGTH_OFFSET=14. Nonzero sentinels prove the reads.
        let mut ops_buf = vec![0_u8; 112].into_boxed_slice();
        ops_buf[0..2].copy_from_slice(&SYN_OSD_OP_READ.to_ne_bytes());
        ops_buf[6..14].copy_from_slice(&SYN_EXTENT_OFFSET.to_ne_bytes());
        ops_buf[14..22].copy_from_slice(&SYN_EXTENT_LENGTH.to_ne_bytes());

        let req_state = Box::new(ReqState {
            trans_id_len: 14, // strlen("bench-trans-id")
            _pad: 0,
            trans_id_ptr: trans_id.as_ptr() as u64,
        });

        let syn_op = Box::new(SynOp {
            tid: SYN_TID,
            cid: SYN_CID,
            target_osd: SYN_TARGET_OSD,
            name_len: SYN_NAME_LEN,
            name_ptr: object_name.as_ptr() as u64,
            rw: 0x0020, // CEPH_OSD_FLAG_WRITE, an arbitrary nonzero u16
            pool: SYN_POOL,
            pg_seed: SYN_PG_SEED,
            acting_start: acting.as_ptr() as u64,
            acting_finish: unsafe { acting.as_ptr().add(acting.len()) } as u64,
            ops_start: ops_buf.as_ptr() as u64,
            ops_size: SYN_OPS_SIZE,
        });

        Self {
            req_state,
            syn_op,
            _trans_id: trans_id,
            _object_name: object_name,
            _acting: acting,
            _ops_buf: ops_buf,
        }
    }

    pub fn req_state_ptr(&self) -> *const ReqState {
        &*self.req_state as *const ReqState
    }

    pub fn syn_op_ptr(&self) -> *const SynOp {
        &*self.syn_op as *const SynOp
    }
}

impl Default for SynState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Synthetic target functions. Each is exported (`#[no_mangle]`), never inlined,
// and reads a distinct set of members so identical-code-folding cannot merge two
// of them onto one address (which would make a uprobe attach to the wrong
// function). The bodies are otherwise irrelevant: the uprobe fires at ENTRY and
// reads registers, so all that matters is the argument arrives in the first
// integer register and the symbol survives in the ELF.
// ---------------------------------------------------------------------------

/// Register layout for `RGWREST::get_handler` (`req_state*` in arg0).
#[no_mangle]
#[inline(never)]
pub extern "C" fn syn_get_handler(rs: *const ReqState) -> u64 {
    // SAFETY: caller passes a valid `&ReqState`; read keeps the arg live.
    unsafe { (*rs).trans_id_len as u64 ^ (*rs).trans_id_ptr }
}

/// Register layout for `req_state::~req_state` (`this` in arg0).
#[no_mangle]
#[inline(never)]
pub extern "C" fn syn_req_state_dtor(rs: *const ReqState) -> u64 {
    // SAFETY: as above; distinct body so ICF cannot merge it with get_handler.
    unsafe { ((*rs).trans_id_ptr).wrapping_add((*rs).trans_id_len as u64) }
}

/// Register layout for `Objecter::_send_op` (submit struct in arg0).
#[no_mangle]
#[inline(never)]
pub extern "C" fn syn_send_op(op: *const SynOp) -> u64 {
    // SAFETY: caller passes a valid `&SynOp`.
    unsafe { (*op).tid ^ (*op).cid ^ (*op).pool }
}

/// Register layout for `Objecter::_finish_op` (submit struct in arg0).
#[no_mangle]
#[inline(never)]
pub extern "C" fn syn_finish_op(op: *const SynOp) -> u64 {
    // SAFETY: caller passes a valid `&SynOp`; distinct body from send_op.
    unsafe { (*op).cid.wrapping_sub((*op).tid) ^ (*op).ops_size as u64 }
}

/// Register layout for `rgw_rados_operate` (`dpp` in arg0). We reuse the
/// `req_state*` as the dpp identity, exactly as Ceph does when the dpp is the
/// req_state.
#[no_mangle]
#[inline(never)]
pub extern "C" fn syn_rados_operate(dpp: *const c_void) -> u64 {
    (dpp as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

/// The trivial-trap target: probed by the bench-only always-return-0 program to
/// isolate pure trap cost. No pointer deref; a plain scalar so its baseline is
/// the cheapest possible call.
#[no_mangle]
#[inline(never)]
pub extern "C" fn syn_trap_target(x: u64) -> u64 {
    x.wrapping_mul(0x2545_F491_4F6C_DD1D)
}

// ---------------------------------------------------------------------------
// Descriptor set: (probe id, descriptor) pairs. Populated into `hprobes` before
// attach so every real program takes its full path.
// ---------------------------------------------------------------------------

/// Base probe ids, matching `FUNCTION_BASE_IDS` in src/dwarf_json.rs.
pub const SEND_OP_BASE: i32 = 0;
pub const FINISH_OP_BASE: i32 = 20;
pub const GET_HANDLER_BASE: i32 = 30;
pub const REQ_STATE_DTOR_BASE: i32 = 50;
pub const RADOS_OPERATE_READ_BASE: i32 = 60;

fn off(offset: usize) -> i32 {
    i32::try_from(offset).expect("synthetic struct offsets fit in i32")
}

/// All `hprobes` entries needed for the five real programs to run their full
/// bodies against the synthetic functions. Returned as `(key, VarField)` pairs.
pub fn descriptor_set() -> Vec<(i32, VarFieldK)> {
    use std::mem::offset_of;
    let reg = ARG0_REG;

    let mut entries = Vec::new();

    // get_handler: slot 30 reads trans_id_len (int), slot 31 reads trans_id_ptr
    // (pointer). The argument register value itself becomes the req_state* bridge
    // key (register-only, since these descriptors are stack == false).
    entries.push((
        GET_HANDLER_BASE,
        reg_member(reg, off(offset_of!(ReqState, trans_id_len))),
    ));
    entries.push((
        GET_HANDLER_BASE + 1,
        reg_member(reg, off(offset_of!(ReqState, trans_id_ptr))),
    ));

    // send_op: slots 0..=11.
    let send: [(i32, usize); 12] = [
        (0, offset_of!(SynOp, tid)),
        (1, offset_of!(SynOp, cid)),
        (2, offset_of!(SynOp, target_osd)),
        (3, offset_of!(SynOp, name_len)),
        (4, offset_of!(SynOp, name_ptr)),
        (5, offset_of!(SynOp, rw)),
        (6, offset_of!(SynOp, pool)),
        (7, offset_of!(SynOp, pg_seed)),
        (8, offset_of!(SynOp, acting_start)),
        (9, offset_of!(SynOp, acting_finish)),
        (10, offset_of!(SynOp, ops_start)),
        (11, offset_of!(SynOp, ops_size)),
    ];
    for (slot, offset) in send {
        entries.push((SEND_OP_BASE + slot, reg_member(reg, off(offset))));
    }

    // finish_op: slots 20 (tid), 21 (cid) -- the same client_op_key send_op
    // inserted, so the lookup hits and the RADOS_OP event is emitted.
    entries.push((FINISH_OP_BASE, reg_member(reg, off(offset_of!(SynOp, tid)))));
    entries.push((
        FINISH_OP_BASE + 1,
        reg_member(reg, off(offset_of!(SynOp, cid))),
    ));

    // req_state destructor: slot 50, raw `this` pointer (register only).
    entries.push((REQ_STATE_DTOR_BASE, raw_pointer(reg)));

    // rgw_rados_operate (read overload): slot 60, raw `dpp` pointer.
    entries.push((RADOS_OPERATE_READ_BASE, raw_pointer(reg)));

    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_set_covers_every_probe_slot() {
        let set = descriptor_set();
        let keys: Vec<i32> = set.iter().map(|(k, _)| *k).collect();
        // send_op 0..=11
        for slot in 0..=11 {
            assert!(keys.contains(&slot), "missing send_op slot {slot}");
        }
        // finish_op 20,21; get_handler 30,31; dtor 50; operate 60
        for slot in [20, 21, 30, 31, 50, 60] {
            assert!(keys.contains(&slot), "missing slot {slot}");
        }
        assert_eq!(set.len(), 12 + 2 + 2 + 1 + 1);
    }

    #[test]
    fn backing_pointers_are_nonzero_and_stable() {
        let state = SynState::new();
        assert_ne!(state.req_state.trans_id_ptr, 0);
        assert_ne!(state.syn_op.name_ptr, 0);
        assert_ne!(state.syn_op.acting_start, 0);
        // acting_finish - acting_start must be a whole number of ints.
        let bytes = state.syn_op.acting_finish - state.syn_op.acting_start;
        assert_eq!(bytes, 3 * std::mem::size_of::<i32>() as u64);
        assert_ne!(state.syn_op.ops_start, 0);
        // Pointers survive a move of SynState (Box contents do not move).
        let p1 = state.req_state_ptr();
        let op1 = state.syn_op_ptr();
        let moved = state;
        assert_eq!(moved.req_state_ptr(), p1);
        assert_eq!(moved.syn_op_ptr(), op1);
    }

    #[test]
    fn synthetic_functions_have_distinct_addresses() {
        // ICF must not have merged two probe targets onto one address, or a
        // uprobe would attach to the wrong function.
        let addrs = [
            syn_get_handler as usize,
            syn_req_state_dtor as usize,
            syn_send_op as usize,
            syn_finish_op as usize,
            syn_rados_operate as usize,
            syn_trap_target as usize,
        ];
        for i in 0..addrs.len() {
            for j in (i + 1)..addrs.len() {
                assert_ne!(addrs[i], addrs[j], "functions {i} and {j} share an address");
            }
        }
    }
}
