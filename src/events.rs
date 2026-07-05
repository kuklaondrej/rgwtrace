#![allow(dead_code)]

use serde::Serialize;

pub const MAX_ACTING: usize = 16;
pub const MAX_TRANS_ID: usize = 128;
pub const MAX_OBJECT_NAME: usize = 128;
pub const MAX_RADOS_OPS: usize = 3;

// Reserved in the ABI (mirrored in bpf/rgwtrace_events.h) but never emitted:
// the single-marker model uses only REQUEST_END. Kept for byte-for-byte ABI
// stability; there is deliberately no TraceEvent::RequestStart variant.
pub const RGWTRACE_EVENT_REQUEST_START: u32 = 1;
pub const RGWTRACE_EVENT_REQUEST_END: u32 = 2;
pub const RGWTRACE_EVENT_RADOS_OP: u32 = 3;

pub const RGWTRACE_TRUNC_TRANS_ID: u32 = 1 << 0;
pub const RGWTRACE_TRUNC_OBJECT_NAME: u32 = 1 << 1;
pub const RGWTRACE_TRUNC_ACTING: u32 = 1 << 2;
pub const RGWTRACE_TRUNC_RADOS_OPS: u32 = 1 << 3;
pub const RGWTRACE_TRUNC_CLS_NAME: u32 = 1 << 4;
pub const RGWTRACE_TRUNC_METHOD_NAME: u32 = 1 << 5;

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
    pub flags: u32,
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
    pub send_tid: u32,
    pub target_osd: u32,
    pub pg_seed: u32,
    pub rw: u16,
    pub ops_size: u32,
    pub flags: u32,
    pub acting: [i32; MAX_ACTING],
    pub ops: [u16; MAX_RADOS_OPS],
    pub cls_ops: [RawClsOp; MAX_RADOS_OPS],
    pub trans_id: [u8; MAX_TRANS_ID],
    pub object_name: [u8; MAX_OBJECT_NAME],
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TraceEvent {
    RequestEnd(RequestEvent),
    RadosOp(RadosEvent),
}

impl TraceEvent {
    pub fn add_timestamp_offset(&mut self, offset_ns: u64) {
        fn add_offset(timestamp: &mut u64, offset_ns: u64) {
            if *timestamp != 0 {
                *timestamp = timestamp.saturating_add(offset_ns);
            }
        }

        match self {
            TraceEvent::RequestEnd(request) => {
                add_offset(&mut request.start_ns, offset_ns);
                add_offset(&mut request.end_ns, offset_ns);
            }
            TraceEvent::RadosOp(rados) => {
                add_offset(&mut rados.sent_ns, offset_ns);
                add_offset(&mut rados.finish_ns, offset_ns);
            }
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RequestEvent {
    pub start_ns: u64,
    pub end_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub trans_id: String,
    pub truncation: CaptureTruncation,
}

#[derive(Clone, Debug, Serialize)]
pub struct RadosEvent {
    pub pid: u32,
    pub send_tid: u32,
    pub cid: u64,
    pub tid: u64,
    pub sent_ns: u64,
    pub finish_ns: u64,
    pub duration_ns: u64,
    pub pool: u64,
    pub target_osd: u32,
    pub pg_seed: u32,
    pub acting: Vec<i32>,
    pub rw: RadosDirection,
    pub object_name: String,
    pub trans_id: String,
    pub truncation: CaptureTruncation,
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

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct CaptureTruncation {
    pub trans_id: bool,
    pub object_name: bool,
    pub acting: bool,
    pub rados_ops: bool,
    pub cls_name: bool,
    pub method_name: bool,
}

impl CaptureTruncation {
    pub fn from_flags(flags: u32) -> Self {
        Self {
            trans_id: flags & RGWTRACE_TRUNC_TRANS_ID != 0,
            object_name: flags & RGWTRACE_TRUNC_OBJECT_NAME != 0,
            acting: flags & RGWTRACE_TRUNC_ACTING != 0,
            rados_ops: flags & RGWTRACE_TRUNC_RADOS_OPS != 0,
            cls_name: flags & RGWTRACE_TRUNC_CLS_NAME != 0,
            method_name: flags & RGWTRACE_TRUNC_METHOD_NAME != 0,
        }
    }

    pub fn names(self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.trans_id {
            names.push("trans_id");
        }
        if self.object_name {
            names.push("object_name");
        }
        if self.acting {
            names.push("acting");
        }
        if self.rados_ops {
            names.push("rados_ops");
        }
        if self.cls_name {
            names.push("cls_name");
        }
        if self.method_name {
            names.push("method_name");
        }
        names
    }
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
        0x1206 => "notify",
        0x1207 => "notify-ack",
        0x1209 => "list-watchers",
        0x1205 => "sparse-read",
        0x120b => "sync_read",
        0x2201 => "write",
        0x2202 => "writefull",
        0x2204 => "zero",
        0x2206 => "append",
        0x220f => "watch",
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
            truncation: CaptureTruncation::from_flags(raw.flags),
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
            send_tid: raw.send_tid,
            cid: raw.cid,
            tid: raw.tid,
            sent_ns: raw.sent_ns,
            finish_ns: raw.finish_ns,
            duration_ns: raw.finish_ns.saturating_sub(raw.sent_ns),
            pool: raw.pool,
            target_osd: raw.target_osd,
            pg_seed: raw.pg_seed,
            acting: raw.acting.into_iter().take_while(|osd| *osd >= 0).collect(),
            rw: if raw.rw & 0x0020 != 0 {
                RadosDirection::Write
            } else {
                RadosDirection::Read
            },
            object_name: nul_terminated_string(&raw.object_name),
            trans_id: nul_terminated_string(&raw.trans_id),
            truncation: CaptureTruncation::from_flags(raw.flags),
            ops,
            offset: raw.offset,
            length: raw.length,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_offset_keeps_zero_end_timestamp() {
        let mut event = TraceEvent::RequestEnd(RequestEvent {
            start_ns: 10,
            end_ns: 0,
            pid: 1,
            tid: 2,
            trans_id: String::new(),
            truncation: CaptureTruncation::default(),
        });

        event.add_timestamp_offset(1000);

        let TraceEvent::RequestEnd(request) = event else {
            panic!("expected request end event");
        };
        assert_eq!(request.start_ns, 1010);
        assert_eq!(request.end_ns, 0);
    }

    #[test]
    fn timestamp_offset_preserves_rados_duration() {
        let mut event = TraceEvent::RadosOp(RadosEvent {
            pid: 1,
            send_tid: 4,
            cid: 2,
            tid: 3,
            sent_ns: 100,
            finish_ns: 125,
            duration_ns: 25,
            pool: 4,
            target_osd: 7,
            pg_seed: 5,
            acting: Vec::new(),
            rw: RadosDirection::Read,
            object_name: String::new(),
            trans_id: String::new(),
            truncation: CaptureTruncation::default(),
            ops: Vec::new(),
            offset: 0,
            length: 0,
        });

        event.add_timestamp_offset(1000);

        let TraceEvent::RadosOp(rados) = event else {
            panic!("expected rados event");
        };
        assert_eq!(rados.sent_ns, 1100);
        assert_eq!(rados.finish_ns, 1125);
        assert_eq!(rados.duration_ns, 25);
    }

    #[test]
    fn converts_raw_request_event() {
        let request = RequestEvent::from(RawRequestEvent {
            start_ns: 10,
            end_ns: 20,
            pid: 42,
            tid: 7,
            flags: RGWTRACE_TRUNC_TRANS_ID,
            trans_id: bytes("tx0001"),
        });

        assert_eq!(request.start_ns, 10);
        assert_eq!(request.end_ns, 20);
        assert_eq!(request.pid, 42);
        assert_eq!(request.tid, 7);
        assert_eq!(request.trans_id, "tx0001");
        assert!(request.truncation.trans_id);
        assert!(!request.truncation.object_name);
    }

    #[test]
    fn converts_raw_rados_event() {
        let mut acting = [-1; MAX_ACTING];
        acting[0] = 1;
        acting[1] = 2;

        let empty_cls_op = RawClsOp {
            cls_name: [0; 8],
            method_name: [0; 32],
        };
        let raw = RawRadosEvent {
            cid: 9,
            tid: 10,
            sent_ns: 200,
            finish_ns: 150,
            pool: 16,
            offset: 64,
            length: 4096,
            pid: 42,
            send_tid: 77,
            target_osd: 7,
            pg_seed: 0x2a,
            rw: 0x0020,
            ops_size: 99,
            flags: RGWTRACE_TRUNC_OBJECT_NAME
                | RGWTRACE_TRUNC_RADOS_OPS
                | RGWTRACE_TRUNC_CLS_NAME
                | RGWTRACE_TRUNC_METHOD_NAME,
            acting,
            ops: [0x2202, 0x1401, 0xffff],
            cls_ops: [
                empty_cls_op,
                RawClsOp {
                    cls_name: bytes("cls"),
                    method_name: bytes("method"),
                },
                empty_cls_op,
            ],
            trans_id: bytes("tx0002"),
            object_name: bytes("bucket-object"),
        };

        let event = RadosEvent::from(raw);

        assert_eq!(event.pid, 42);
        assert_eq!(event.send_tid, 77);
        assert_eq!(event.cid, 9);
        assert_eq!(event.tid, 10);
        assert_eq!(event.duration_ns, 0);
        assert_eq!(event.pool, 16);
        assert_eq!(event.target_osd, 7);
        assert_eq!(event.pg_seed, 0x2a);
        assert_eq!(event.acting, vec![1, 2]);
        assert_eq!(event.rw, RadosDirection::Write);
        assert_eq!(event.object_name, "bucket-object");
        assert_eq!(event.trans_id, "tx0002");
        assert_eq!(event.offset, 64);
        assert_eq!(event.length, 4096);
        assert_eq!(event.ops.len(), MAX_RADOS_OPS);
        assert_eq!(event.ops[0].name, "writefull");
        assert_eq!(event.ops[1].name, "call");
        assert_eq!(event.ops[1].class.as_deref(), Some("cls"));
        assert_eq!(event.ops[1].method.as_deref(), Some("method"));
        assert_eq!(event.ops[2].name, "unknown(0xffff)");
        assert!(event.truncation.object_name);
        assert!(event.truncation.rados_ops);
        assert!(event.truncation.cls_name);
        assert!(event.truncation.method_name);
    }

    fn bytes<const N: usize>(value: &str) -> [u8; N] {
        let mut bytes = [0; N];
        bytes[..value.len()].copy_from_slice(value.as_bytes());
        bytes
    }
}
