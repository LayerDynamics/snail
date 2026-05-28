//! Build script: capture the build target triple and crate version into a
//! generated `build_info.rs` (in `OUT_DIR`) that `bind.rs` includes to expose
//! `clientInfo()`. The target triple is only available to build scripts (via the
//! `TARGET` env var), so this cannot be done with `env!` at compile time.

use std::{env, fs, path::Path};

fn main() {
    let target = env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    let version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_string());

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR is set by cargo");
    let dest = Path::new(&out_dir).join("build_info.rs");
    let contents = format!(
        "/// Crate version, captured at build time.\n\
         pub const BUILD_VERSION: &str = \"{version}\";\n\
         /// Target triple this binding was built for.\n\
         pub const BUILD_TARGET: &str = \"{target}\";\n"
    );
    fs::write(&dest, contents).expect("write build_info.rs");

    println!("cargo:rerun-if-changed=build.rs");
}
