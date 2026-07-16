// SPDX-License-Identifier: GPL-2.0-only
use std::env;

fn main() {
    // The real programs live in the parent crate's bpf/ tree; rebuild if they
    // change so the bench never measures a stale skeleton.
    println!("cargo:rerun-if-changed=../bpf/rgwtrace.bpf.c");
    println!("cargo:rerun-if-changed=../bpf/rgwtrace_events.h");
    println!("cargo:rerun-if-changed=../bpf/ceph_abi.h");
    println!("cargo:rerun-if-changed=../bpf/bpf_utils.h");
    println!("cargo:rerun-if-changed=bpf/bench_trap.bpf.c");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }

    build_bpf();
}

#[cfg(target_os = "linux")]
fn build_bpf() {
    use std::path::PathBuf;

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"));
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let repo_root = manifest
        .parent()
        .expect("bench crate has a parent workspace root")
        .to_path_buf();
    let bpf_dir = repo_root.join("bpf");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH must be set");
    let (bpf_arch, multiarch_include) = match target_arch.as_str() {
        "x86_64" => ("-D__TARGET_ARCH_x86", "/usr/include/x86_64-linux-gnu"),
        "aarch64" => ("-D__TARGET_ARCH_arm64", "/usr/include/aarch64-linux-gnu"),
        other => panic!("unsupported BPF target architecture {other}"),
    };

    // 1. The REAL rgwtrace programs, byte-for-byte the same source the tool
    //    ships. This is what makes the measurement meaningful: we attach the
    //    exact programs, not a re-implementation.
    let real_skel = out_dir.join("rgwtrace.skel.rs");
    libbpf_cargo::SkeletonBuilder::new()
        .source(bpf_dir.join("rgwtrace.bpf.c"))
        .clang_args([
            "-I".as_ref(),
            bpf_dir.as_os_str(),
            "-I".as_ref(),
            multiarch_include.as_ref(),
            bpf_arch.as_ref(),
        ])
        .build_and_generate(&real_skel)
        .expect("failed to build rgwtrace BPF skeleton for the bench harness");

    // 2. The bench-only trivial trap program.
    let trap_skel = out_dir.join("bench_trap.skel.rs");
    let trap_src = manifest.join("bpf").join("bench_trap.bpf.c");
    libbpf_cargo::SkeletonBuilder::new()
        .source(&trap_src)
        .clang_args([
            "-I".as_ref(),
            bpf_dir.as_os_str(),
            "-I".as_ref(),
            multiarch_include.as_ref(),
            bpf_arch.as_ref(),
        ])
        .build_and_generate(&trap_skel)
        .expect("failed to build bench_trap BPF skeleton");
}

#[cfg(not(target_os = "linux"))]
fn build_bpf() {
    panic!("BPF skeleton generation is only supported on Linux");
}
