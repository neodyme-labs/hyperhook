# Examples

## fuzz_example_unix

Requires target `x86_64-unknown-linux-gnu`: `rustup target add x86_64-unknown-linux-gnu`

Build:
```
RUSTFLAGS="-C target-feature=-crt-static" cargo build --example fuzz_example_unix --target x86_64-unknown-linux-gnu
```

## hook_example_windows

Requires target `x86_64-pc-windows-gnu` and `gcc-mingw-w64`:
```
sudo apt install gcc-mingw-w64
rustup target add x86_64-pc-windows-gnu
```

Build:
```
RUSTFLAGS="-C target-feature=-crt-static" cargo build --example hook_example_windows --target x86_64-pc-windows-gnu
```