# HyperHook

Hyperhook is a cross-platform harnessing framework designed for Nyx-based fuzzers.

It provides essential functionalities such as issuing hypercalls, managing function hooks and detours, setting up resident memory pages, and enabling custom signal and exception handlers. Currently, it supports userspace targets on both Linux and Windows.

## Features

- Function detours by address or name
- Module and function resolving
- Signal and exception handling
- Nyx guest-to-host communication via hypercalls
- Config file for PT trace modules
- Malloc resident pages for fuzz input
- Debug logging to host via hypercalls

## Resources

- [HyperHook example usage with Nyx and LibAFL](https://neodyme.io/blog/hyperhook)
- [kAFL's documentation for Nyx setup](https://intellabs.github.io/kAFL/)
- [Generic LibAFL fuzzer for Nyx](https://github.com/AFLplusplus/LibAFL/tree/main/fuzzers/full_system/nyx_launcher)

## Getting Started

We provide [examples](https://github.com/neodyme-labs/hyperhook/tree/main/examples) for both Windows and Linux.

There is also a [selffuzz](https://github.com/neodyme-labs/hyperhook/tree/main/examples/selffuzz) example for testing purposes.

For a detailed setup instructions check out our [blog post](https://neodyme.io/blog/hyperhook).

## Known Issues

When building HyperHook for Windows targets in release mode, [the hooking seems to be unstable](https://github.com/Hpmason/retour-rs/issues/59).