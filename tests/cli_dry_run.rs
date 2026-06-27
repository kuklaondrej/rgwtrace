use std::process::Command;

use serde_json::Value;

#[test]
fn dry_run_with_imported_dwarf_emits_empty_trace_document() {
    let output = Command::new(env!("CARGO_BIN_EXE_rgwtrace"))
        .args([
            "--import-json",
            "tests/fixtures/minimal_dwarf.json",
            "--dry-run",
            "--output",
            "json",
            "--service-name",
            "rgwtrace-test",
        ])
        .output()
        .expect("failed to run rgwtrace");

    assert!(
        output.status.success(),
        "rgwtrace failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let json: Value = serde_json::from_slice(&output.stdout).expect("stdout must be JSON");

    assert_eq!(json["dwarf"]["version"], "19.2.3-test");
    assert_eq!(json["dwarf"]["arch"], "amd64");
    assert_eq!(json["dwarf"]["module_count"], 2);
    assert_eq!(json["dwarf"]["hprobe_entries"], 73);
    assert_eq!(json["trace"]["service_name"], "rgwtrace-test");
    assert_eq!(json["trace"]["spans"].as_array().unwrap().len(), 0);
    assert_eq!(json["trace"]["diagnostics"]["events_decoded"], 0);
    assert_eq!(json["trace"]["diagnostics"]["spans_produced"], 0);
}

#[test]
fn export_dwarf_json_emits_full_loaded_probe_metadata() {
    let output = Command::new(env!("CARGO_BIN_EXE_rgwtrace"))
        .args([
            "--import-json",
            "tests/fixtures/minimal_dwarf.json",
            "--export-dwarf-json",
        ])
        .output()
        .expect("failed to run rgwtrace");

    assert!(
        output.status.success(),
        "rgwtrace failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let json: Value = serde_json::from_slice(&output.stdout).expect("stdout must be JSON");

    assert_eq!(json["version"], "19.2.3-test");
    assert_eq!(json["arch"], "amd64");
    assert_eq!(json["libceph-common.so.2"]["build_id"], "111111");
    assert_eq!(
        json["libceph-common.so.2"]["func2pc"]["Objecter::_send_op"],
        4096
    );
    assert_eq!(json["radosgw"]["build_id"], "222222");
    assert_eq!(json["trace"], Value::Null);
}
