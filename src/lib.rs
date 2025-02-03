//! Hyperhook is a cross-platform harnessing framework designed for Nyx-based fuzzers.
//!
//! It provides essential functionalities for fuzzing, triaging, and tracing/debugging executions,
//! offering platform-specific support for issuing hypercalls, managing detours with raw detour patches,
//! setting up resident memory pages, and enabling custom signal and exception handlers.
#![doc = document_features::document_features!()]

pub mod config;
pub mod hooking;
pub mod misc;
pub mod modules;
pub mod nyx;
