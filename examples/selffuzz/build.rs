extern crate cc;

fn main() {
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        cc::Build::new()
            .file("src/win_to_fuzz.c")
            .compile("fuzz_case");
    } else {
        cc::Build::new()
            .file("src/unix_to_fuzz.c")
            .compile("fuzz_case");
    }
}
