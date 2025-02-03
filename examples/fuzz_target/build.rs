use std::process::Command;

fn main() {
    // If run in Kernel mode, libgcc_s.so.1 need to be loaded as a dependency
    Command::new("gcc")
        .args(["src/to_fuzz.c", "-o", "target/debug/to_fuzz", "-g"])
        .spawn()
        .expect("command failed to start");

    println!("cargo:rerun-if-changed=src/to_fuzz.c");
}
