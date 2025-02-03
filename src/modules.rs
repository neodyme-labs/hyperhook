/// Defines the start and end addresses of a memory range and is used for representing memory address ranges in the library.
#[derive(Debug, Default)]
pub struct AddressRange {
    pub start: u64,
    pub end: u64,
    pub index: u64,
}

#[cfg(unix)]
#[path = "modules_unix.rs"]
pub mod modules_impl;

#[cfg(windows)]
#[path = "modules_windows.rs"]
pub mod modules_impl;

pub use modules_impl::*;
