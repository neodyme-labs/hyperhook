# selffuzz

## Linux

Build:

`RUSTFLAGS='-C target-feature=+crt-static' cargo build --target x86_64-unknown-linux-gnu`

Setup Nyx directory for kernel mode fuzzing:

`./setup_nyx_linux.sh`

## Windows

Build:

`RUSTFLAGS='-C target-feature=+crt-static' cargo build --target x86_64-pc-windows-gnu`

