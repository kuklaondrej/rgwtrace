#![allow(dead_code)]

use serde::Serialize;

pub const MAX_ACTING: usize = 16;
pub const MAX_TRANS_ID: usize = 128;
pub const MAX_OBJECT_NAME: usize = 128;
pub const MAX_RADOS_OPS: usize = 3;

pub const RGWTRACE_EVENT_REQUEST_START: u32 = 1;
pub const RGWTRACE_EVENT_REQUEST_END: u32 = 2;
pub const RGWTRACE_EVENT_RADOS_OP: u32 = 3;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RawClsOp {
    pub cls_name: [u8; 8],
    pub method_name: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RawRequestEvent {
    pub start_ns: u64,
    pub end_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub trans_id: [u8; MAX_TRANS_ID],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RawRadosEvent {
    pub cid: u64,
    pub tid: u64,
    pub sent_ns: u64,
    pub finish_ns: u64,
    pub pool: u64,
    pub offset: u64,
    pub length: u64,
    pub pid: u32,
    pub target_osd: u32,
    pub pg_seed: u32,
    pub rw: u16,
    pub ops_size: u32,
    pub acting: [i32; MAX_ACTING],
    pub ops: [u16; MAX_RADOS_OPS],
    pub cls_ops: [RawClsOp; MAX_RADOS_OPS],
    pub trans_id: [u8; MAX_TRANS_ID],
    pub object_name: [u8; MAX_OBJECT_NAME],
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TraceEvent {
    RequestStart(RequestEvent),
    RequestEnd(RequestEvent),
    RadosOp(RadosEvent),
}

#[derive(Clone, Debug, Serialize)]
pub struct RequestEvent {
    pub start_ns: u64,
    pub end_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub trans_id: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct RadosEvent {
    pub pid: u32,
    pub cid: u64,
    pub tid: u64,
    pub sent_ns: u64,
    pub finish_ns: u64,
    pub duration_ns: u64,
    pub pool: u64,
    pub pg_seed: u32,
    pub acting: Vec<i32>,
    pub rw: RadosDirection,
    pub object_name: String,
    pub trans_id: String,
    pub ops: Vec<RadosOp>,
    pub offset: u64,
    pub length: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RadosDirection {
    Read,
    Write,
}

#[derive(Clone, Debug, Serialize)]
pub struct RadosOp {
    pub code: u16,
    pub name: String,
    pub class: Option<String>,
    pub method: Option<String>,
}

pub fn nul_terminated_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

pub fn rados_op_name(code: u16) -> String {
    match code {
        0x1201 => "read",
        0x1202 => "stat",
        0x1203 => "mapext",
        0x1205 => "sparse-read",
        0x120b => "sync_read",
        0x2201 => "write",
        0x2202 => "writefull",
        0x2204 => "zero",
        0x2206 => "append",
        0x1211 => "omap-get-keys",
        0x2215 => "omap-set-vals",
        0x1220 => "cmpext",
        0x1401 => "call",
        _ => return format!("unknown({code:#x})"),
    }
    .to_string()
}

impl From<RawRequestEvent> for RequestEvent {
    fn from(raw: RawRequestEvent) -> Self {
        Self {
            start_ns: raw.start_ns,
            end_ns: raw.end_ns,
            pid: raw.pid,
            tid: raw.tid,
            trans_id: nul_terminated_string(&raw.trans_id),
        }
    }
}

impl From<RawRadosEvent> for RadosEvent {
    fn from(raw: RawRadosEvent) -> Self {
        let ops_size = (raw.ops_size as usize).min(MAX_RADOS_OPS);
        let ops = raw.ops[..ops_size]
            .iter()
            .enumerate()
            .map(|(idx, code)| {
                let cls_op = raw.cls_ops[idx];
                let class = nul_terminated_string(&cls_op.cls_name);
                let method = nul_terminated_string(&cls_op.method_name);
                RadosOp {
                    code: *code,
                    name: rados_op_name(*code),
                    class: (!class.is_empty()).then_some(class),
                    method: (!method.is_empty()).then_some(method),
                }
            })
            .collect();

        Self {
            pid: raw.pid,
            cid: raw.cid,
            tid: raw.tid,
            sent_ns: raw.sent_ns,
            finish_ns: raw.finish_ns,
            duration_ns: raw.finish_ns.saturating_sub(raw.sent_ns),
            pool: raw.pool,
            pg_seed: raw.pg_seed,
            acting: raw.acting.into_iter().take_while(|osd| *osd >= 0).collect(),
            rw: if raw.rw & 0x0020 != 0 {
                RadosDirection::Write
            } else {
                RadosDirection::Read
            },
            object_name: nul_terminated_string(&raw.object_name),
            trans_id: nul_terminated_string(&raw.trans_id),
            ops,
            offset: raw.offset,
            length: raw.length,
        }
    }
}
