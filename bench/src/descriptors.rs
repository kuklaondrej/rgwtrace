// SPDX-License-Identifier: GPL-2.0-only
//! Synthetic `hprobes` descriptors.
//!
//! Byte-for-byte mirror of `struct VarField` from bpf/ceph_abi.h (and of
//! `VarFieldKernel` in src/dwarf_json.rs). The real BPF programs look their
//! descriptor up in the `hprobes` map keyed by probe id and use it to locate a
//! target-function argument. We hand-build descriptors whose register + member
//! layout matches the synthetic target functions, so each real program executes
//! its FULL body instead of bailing on a missing/invalid descriptor.
//!
//! Two descriptor shapes are used, matching what the BPF side consumes:
//!
//! * [`reg_member`] -- a register base plus a single member offset. The BPF
//!   helper `fetch_var_member_addr` returns `reg_value + fields[1].offset`, and
//!   the program then `bpf_probe_read_user`s the field there. Used by the
//!   get_handler / send_op / finish_op slots, all of which read struct members
//!   through a pointer argument.
//! * [`raw_pointer`] -- register only. `fetch_param_ptr` returns the register
//!   value verbatim (it refuses a stack-located descriptor). Used by the
//!   req_state destructor (`this`) and rgw_rados_operate (`dpp`) slots, which
//!   treat the pointer value as an opaque identity/bridge key.

/// DWARF register number for x86-64 `rdi` (first integer argument). Matches
/// `fetch_register(reg == 5)` -> pt_regs offset 112 in bpf/bpf_utils.h. Every
/// synthetic target function below takes its pointer as the first argument, so
/// every descriptor reads `rdi`.
#[cfg(target_arch = "x86_64")]
pub const ARG0_REG: i32 = 5;

/// DWARF/AAPCS register number for aarch64 `x0` (first integer argument);
/// `fetch_register` maps `reg` directly to `regs[reg]` there.
#[cfg(target_arch = "aarch64")]
pub const ARG0_REG: i32 = 0;

/// Mirror of `struct VarLocation` (bpf/ceph_abi.h): `{ int reg; int offset; bool stack; }`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VarLocationK {
    pub reg: i32,
    pub offset: i32,
    pub stack: bool,
}

/// Mirror of `struct Field`: `{ int offset; bool pointer; }`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FieldK {
    pub offset: i32,
    pub pointer: bool,
}

/// Mirror of `struct VarField`: `{ VarLocation varloc; Field fields[10]; int size; }`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VarFieldK {
    pub varloc: VarLocationK,
    pub fields: [FieldK; 10],
    pub size: i32,
}

impl VarFieldK {
    /// Bytes for `bpf_map_update_elem` into `hprobes` (value = `struct VarField`),
    /// written field by field into a zeroed buffer: the struct has implicit
    /// padding after each `bool`, and viewing it as `&[u8]` would read those
    /// uninitialized bytes (undefined behavior).
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut out = vec![0_u8; std::mem::size_of::<VarFieldK>()];
        out[0..4].copy_from_slice(&self.varloc.reg.to_ne_bytes());
        out[4..8].copy_from_slice(&self.varloc.offset.to_ne_bytes());
        out[8] = u8::from(self.varloc.stack);
        for (idx, field) in self.fields.iter().enumerate() {
            let base = 12 + idx * 8;
            out[base..base + 4].copy_from_slice(&field.offset.to_ne_bytes());
            out[base + 4] = u8::from(field.pointer);
        }
        out[92..96].copy_from_slice(&self.size.to_ne_bytes());
        out
    }
}

/// A register-base + single-member-offset descriptor.
///
/// `fetch_var_member_addr` (bpf/bpf_utils.h) with `stack == false` computes
/// `addr = reg_value + fields[1].offset`, then the `for i in 2..size` loop is a
/// no-op because `size == 2`. So the program reads its field at
/// `reg_value + member_offset`.
pub fn reg_member(reg: i32, member_offset: i32) -> VarFieldK {
    let mut vf = VarFieldK {
        varloc: VarLocationK {
            reg,
            offset: 0,
            stack: false,
        },
        fields: [FieldK::default(); 10],
        size: 2,
    };
    vf.fields[1].offset = member_offset;
    vf
}

/// A register-only raw-pointer descriptor. `fetch_param_ptr` returns the
/// register value directly (and returns 0 for a stack-located descriptor, which
/// this never is). `size`/`fields` are unused by that helper.
pub fn raw_pointer(reg: i32) -> VarFieldK {
    VarFieldK {
        varloc: VarLocationK {
            reg,
            offset: 0,
            stack: false,
        },
        fields: [FieldK::default(); 10],
        size: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varfield_matches_kernel_struct_size() {
        // struct VarField = VarLocation(12) + Field[10](8*10) + int(4) = 96.
        // A mismatch here means the hprobes value size disagrees with the BPF
        // map and every descriptor write would be rejected or misread.
        assert_eq!(std::mem::size_of::<VarLocationK>(), 12);
        assert_eq!(std::mem::size_of::<FieldK>(), 8);
        assert_eq!(std::mem::size_of::<VarFieldK>(), 96);
    }

    #[test]
    fn reg_member_encodes_offset_in_field_one() {
        let vf = reg_member(5, 40);
        assert_eq!(vf.varloc.reg, 5);
        assert!(!vf.varloc.stack);
        assert_eq!(vf.fields[1].offset, 40);
        assert_eq!(vf.size, 2);
        assert_eq!(vf.as_bytes().len(), 96);
    }

    #[test]
    fn raw_pointer_is_register_only() {
        let vf = raw_pointer(5);
        assert_eq!(vf.varloc.reg, 5);
        assert!(!vf.varloc.stack);
    }
}
