use std::env;

fn main() {
    println!("cargo:rerun-if-changed=bpf/rgwtrace.bpf.c");
    println!("cargo:rerun-if-changed=bpf/rgwtrace_events.h");
    println!("cargo:rerun-if-changed=bpf/ceph_abi.h");
    println!("cargo:rerun-if-changed=bpf/bpf_utils.h");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }

    build_bpf();
}

#[cfg(target_os = "linux")]
fn build_bpf() {
    use std::path::PathBuf;

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"));
    let skel = out_dir.join("rgwtrace.skel.rs");

    libbpf_cargo::SkeletonBuilder::new()
        .source("bpf/rgwtrace.bpf.c")
        .clang_args(["-I", "bpf"])
        .build_and_generate(&skel)
        .expect("failed to build rgwtrace BPF skeleton");
}

#[cfg(not(target_os = "linux"))]
fn build_bpf() {
    panic!("BPF skeleton generation is only supported on Linux");
}
