use std::{env, path::PathBuf};

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/simple.bpf.c";
const WINDOW: &str = "src/bpf/window.bpf.h";
const VMLINUX: &str = "../bpf";

fn main() {
    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("simple.skel.rs");

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args(format!("-I{VMLINUX}"))
        .build_and_generate(out)
        .expect("bpf compilation failed");

    println!("cargo:rerun-if-changed={}", SRC);
    println!("cargo:rerun-if-changed={}", WINDOW);
}
