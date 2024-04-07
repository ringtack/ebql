use std::{env, path::PathBuf};

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/simple_1.bpf.c";
const HDR: &str = "src/bpf/simple_1.bpf.h";
const WINDOW: &str = "src/bpf/window.bpf.h";
const JOIN: &str = "src/bpf/join_simple_1_simple_2.bpf.h";
const VMLINUX: &str = "../bpf";

fn main() {
    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("simple_1.skel.rs");

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args(format!("-I{VMLINUX}"))
        .build_and_generate(out)
        .expect("bpf compilation failed");

    println!("cargo:rerun-if-changed={}", SRC);
    println!("cargo:rerun-if-changed={}", HDR);
    println!("cargo:rerun-if-changed={}", WINDOW);
    println!("cargo:rerun-if-changed={}", JOIN);
}
