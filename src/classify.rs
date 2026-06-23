use serde::Serialize;

use crate::events::RadosEvent;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestClass {
    S3Request,
    RgwBackground,
    RgwStartup,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RadosRole {
    Data,
    BucketIndex,
    BucketMeta,
    UserMeta,
    AuthMeta,
    Gc,
    Notify,
    Sync,
    Config,
    Unknown,
}

pub fn classify_request(trans_id: &str, object_name: Option<&str>) -> RequestClass {
    if !trans_id.is_empty() {
        return RequestClass::S3Request;
    }

    let Some(object_name) = object_name else {
        return RequestClass::Unknown;
    };

    match classify_background_object(object_name) {
        Some(RadosRole::Config) => RequestClass::RgwStartup,
        Some(_) => RequestClass::RgwBackground,
        None => RequestClass::Unknown,
    }
}

pub fn classify_rados(event: &RadosEvent) -> RadosRole {
    let object = event.object_name.as_str();

    if let Some(role) = classify_background_object(object) {
        return role;
    }

    if object.starts_with(".dir.") {
        return RadosRole::BucketIndex;
    }
    if object.starts_with(".bucket.meta.") {
        return RadosRole::BucketMeta;
    }
    if object.ends_with(".buckets") || looks_like_uuid(object) {
        return RadosRole::UserMeta;
    }
    if looks_like_access_key(object) {
        return RadosRole::AuthMeta;
    }
    if !event.trans_id.is_empty() {
        return RadosRole::Data;
    }

    RadosRole::Unknown
}

fn classify_background_object(object: &str) -> Option<RadosRole> {
    if object.starts_with("gc.") || object.starts_with("obj_delete_at_hint.") {
        return Some(RadosRole::Gc);
    }
    if object.starts_with("notify.") {
        return Some(RadosRole::Notify);
    }
    if object.starts_with("bucket.sync-")
        || object.starts_with("data_log")
        || object.starts_with("_sem_setdata_log")
        || object.starts_with("meta.log.")
    {
        return Some(RadosRole::Sync);
    }
    if matches!(
        object,
        "default.realm"
            | "default.region"
            | "default.zonegroup"
            | "region_map"
            | "zone.user"
            | "zone.user.buckets"
            | "script.prerequest."
    ) || object.starts_with("realms.")
        || object.starts_with("realm_names.")
        || object.starts_with("region_info.")
        || object.starts_with("zone_names.")
        || object.starts_with("zonegroup_info.")
        || object.starts_with("zonegroups_names.")
        || object.starts_with("periods.")
        || object.starts_with("zone_info.")
        || object.starts_with("default.zone.")
        || object.starts_with("script.")
    {
        return Some(RadosRole::Config);
    }

    None
}

fn looks_like_access_key(object: &str) -> bool {
    object.len() == 20
        && object
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

fn looks_like_uuid(object: &str) -> bool {
    let bytes = object.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23].into_iter().all(|idx| bytes[idx] == b'-')
        && bytes
            .iter()
            .enumerate()
            .all(|(idx, b)| [8, 13, 18, 23].contains(&idx) || b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{CaptureTruncation, RadosDirection, RadosEvent};

    fn event(object_name: &str, trans_id: &str) -> RadosEvent {
        RadosEvent {
            pid: 42,
            send_tid: 7,
            cid: 1,
            tid: 2,
            sent_ns: 10,
            finish_ns: 20,
            duration_ns: 10,
            pool: 16,
            target_osd: 7,
            pg_seed: 1,
            acting: vec![1, 2, 3],
            rw: RadosDirection::Read,
            object_name: object_name.to_string(),
            trans_id: trans_id.to_string(),
            truncation: CaptureTruncation::default(),
            ops: Vec::new(),
            offset: 0,
            length: 0,
        }
    }

    #[test]
    fn classifies_invalid_access_key_lookup_as_auth_metadata() {
        assert_eq!(
            classify_rados(&event("DLNWHCESVOM3JJWS2QU2", "tx000001196f216d3841357")),
            RadosRole::AuthMeta
        );
    }

    #[test]
    fn classifies_background_objects() {
        assert_eq!(classify_rados(&event("notify.0", "")), RadosRole::Notify);
        assert_eq!(classify_rados(&event("gc.5", "")), RadosRole::Gc);
        assert_eq!(
            classify_rados(&event("bucket.sync-source-hints.", "")),
            RadosRole::Sync
        );
        assert_eq!(classify_rados(&event("data_log.0", "")), RadosRole::Sync);
        assert_eq!(classify_rados(&event("data_log@G3.1", "")), RadosRole::Sync);
        assert_eq!(
            classify_rados(&event("_sem_setdata_log.0", "")),
            RadosRole::Sync
        );
        assert_eq!(
            classify_rados(&event("meta.log.012345.7", "")),
            RadosRole::Sync
        );
        assert_eq!(
            classify_rados(&event("default.zonegroup", "")),
            RadosRole::Config
        );
        assert_eq!(
            classify_rados(&event("zonegroup_info.123", "")),
            RadosRole::Config
        );
        assert_eq!(
            classify_rados(&event("zonegroups_names.default", "")),
            RadosRole::Config
        );
        assert_eq!(
            classify_rados(&event("realm_names.default", "")),
            RadosRole::Config
        );
    }

    #[test]
    fn classifies_all_rados_roles() {
        assert_eq!(classify_rados(&event("object", "tx1")), RadosRole::Data);
        assert_eq!(
            classify_rados(&event(".dir.bucket.1", "tx1")),
            RadosRole::BucketIndex
        );
        assert_eq!(
            classify_rados(&event(".bucket.meta.bucket:marker", "tx1")),
            RadosRole::BucketMeta
        );
        assert_eq!(
            classify_rados(&event("user.buckets", "tx1")),
            RadosRole::UserMeta
        );
        assert_eq!(
            classify_rados(&event("123e4567-e89b-12d3-a456-426614174000", "tx1")),
            RadosRole::UserMeta
        );
        assert_eq!(
            classify_rados(&event("ABCDEFGHIJKLMNOPQRST", "tx1")),
            RadosRole::AuthMeta
        );
        assert_eq!(
            classify_rados(&event("obj_delete_at_hint.1", "")),
            RadosRole::Gc
        );
        assert_eq!(classify_rados(&event("data_log.1", "")), RadosRole::Sync);
        assert_eq!(classify_rados(&event("region_map", "")), RadosRole::Config);
        assert_eq!(
            classify_rados(&event("default.region", "")),
            RadosRole::Config
        );
        assert_eq!(
            classify_rados(&event("region_info.default", "")),
            RadosRole::Config
        );
        assert_eq!(
            classify_rados(&event("zone_names.default", "")),
            RadosRole::Config
        );
        assert_eq!(
            classify_rados(&event("default.realm", "")),
            RadosRole::Config
        );
        assert_eq!(classify_rados(&event("unknown", "")), RadosRole::Unknown);
    }

    #[test]
    fn classifies_request_contexts() {
        assert_eq!(classify_request("tx1", None), RequestClass::S3Request);
        assert_eq!(
            classify_request("", Some("default.realm")),
            RequestClass::RgwStartup
        );
        assert_eq!(
            classify_request("", Some("notify.0")),
            RequestClass::RgwBackground
        );
        assert_eq!(classify_request("", Some("unknown")), RequestClass::Unknown);
        assert_eq!(classify_request("", None), RequestClass::Unknown);
    }
}
