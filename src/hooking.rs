//! Provides functionality for hooking and detouring function calls in HyperHook.
//!
//! It allows adding raw detours for specific functions, enabling and disabling detours, and retrieving the trampoline pointer for a detour.

use std::{collections::HashMap, sync::Mutex};

use once_cell::sync::Lazy;

use retour::RawDetour;

/// A thread-safe global Lazy static instance of `HookManager`.
pub static HOOK_MANAGER: Lazy<Mutex<HookManager>> = Lazy::new(|| Mutex::new(HookManager::new()));

/// A function pointer type representing the signature of the `main` function in C.
#[cfg(target_os = "linux")]
pub type MainFcnPtr =
    unsafe extern "C" fn(libc::c_int, *const *const libc::c_char, *const *const libc::c_char);

/// The original function pointer for the `main` function.
pub static mut MAIN_PTR_ORIGINAL: usize = 0;

/// Manages the raw detour hooks for function calls.
pub struct HookManager {
    raw_detours: HashMap<String, RawDetour>,
}

impl HookManager {
    /// Adds a raw detour for a specified function by name, target, and detour addresses.
    /// # Safety
    /// TODO
    pub unsafe fn add_raw_detour(&mut self, name: &str, target: *const (), detour: *const ()) {
        unsafe {
            let hook = RawDetour::new(target, detour)
                .expect("target or source is not usable for detouring");
            self.raw_detours.insert(name.to_string(), hook);
        }
    }

    /// Enables a detour for a specified function.
    /// # Safety
    /// TODO
    pub unsafe fn enable_detour(&mut self, name: &str) -> bool {
        unsafe {
            let hook = self.raw_detours.get(name);
            if hook.is_none() {
                return false;
            }

            hook.unwrap().enable().is_ok()
        }
    }

    /// Disables a detour for a specified function.
    pub fn disable_detour(&mut self, name: &str) -> bool {
        let hook = self.raw_detours.get(name);
        if hook.is_none() {
            return false;
        }
        unsafe { hook.unwrap().disable().is_ok() }
    }

    // TODO: How to do generics <T> and mem::transmute to get directly a nice trampoline pointer?
    // REF: https://github.com/darfink/detour-rs/blob/3b6f17a8b51ba5b37addc8c4361e5cfbe2875243/tests/lib.rs#L34C33-L34C48
    /// Returns the trampoline pointer for a detour.
    pub fn get_trampoline(&self, name: &str) -> Option<*const ()> {
        self.raw_detours
            .get(name)
            .map(|hook| hook.trampoline() as *const ())
    }

    fn new() -> HookManager {
        HookManager {
            raw_detours: HashMap::new(),
        }
    }
}
