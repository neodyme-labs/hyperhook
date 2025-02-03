use std::{path::Path, process::Command};

use clap::Parser;

/// Search for a pattern in a file and display the lines that contain it.
#[derive(Parser)]
struct Cli {
    /// Path to executable that should be started and injected into
    program_to_inject: String,
    /// Path of the library, relative to target/debug/examples/
    library_name: String,
}
fn main() {
    let args = Cli::parse();
    let libary_fullpath: std::path::PathBuf = Path::new(".")
        .join("target/debug/examples/")
        .join(args.library_name);

    if !libary_fullpath.exists() {
        println!("Library path not found: {:?}", libary_fullpath);
        return;
    }

    Command::new(args.program_to_inject)
        .env("LD_PRELOAD", libary_fullpath.to_str().unwrap())
        .spawn()
        .expect("command failed to start");
}
