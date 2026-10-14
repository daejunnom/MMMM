// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors

fn main() {
    // TARGET is Cargo's compilation target, not the build-script host. Do not
    // print an unrecognized value: a custom target may contain a private path.
    let target = std::env::var("TARGET").unwrap_or_default();
    let admitted = match target.as_str() {
        "x86_64-pc-windows-msvc" => "x86_64-pc-windows-msvc",
        "x86_64-unknown-linux-gnu" => "x86_64-unknown-linux-gnu",
        "aarch64-apple-darwin" => "aarch64-apple-darwin",
        _ => "unsupported",
    };
    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rustc-env=MMMM_OBSERVER_BUILD_TARGET={admitted}");
}
