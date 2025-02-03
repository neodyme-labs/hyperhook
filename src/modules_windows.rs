//! Module for handling modules on Windows systems.

use log::*;

use std::ptr::null_mut;
use winapi::{
    shared::minwindef::MAX_PATH,
    um::{libloaderapi::GetModuleHandleA, psapi::GetModuleBaseNameA, winnt::HANDLE},
};

/// Get the address of a symbol in a module.
#[cfg(target_os = "windows")]
pub fn get_symbol_address(module_name: &str, function_name: &str) -> Option<usize> {
    use std::{ffi::CString, ptr};
    #[cfg(target_os = "windows")]
    use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
    unsafe {
        let module_name: CString = CString::new(module_name).expect("Failed to create CString");
        let mut module = LoadLibraryA(module_name.as_ptr());

        if module_name.is_empty() {
            let mut mod_name: [u8; 260] = [0; MAX_PATH];
            let own_process_handle = usize::MAX as HANDLE;
            let res = GetModuleBaseNameA(
                own_process_handle,
                null_mut(),
                mod_name.as_mut_ptr() as *mut i8,
                MAX_PATH as u32,
            );
            if res == 0 {
                error!("Failed to GetModuleBaseNameA");
                return None;
            }

            let mod_name_len = mod_name.iter().position(|&r| r == 0).unwrap();
            let mod_name_str = std::str::from_utf8(&mod_name[0..mod_name_len]).unwrap();

            let mod_name_str: CString =
                CString::new(mod_name_str).expect("Failed to create CString");
            module = GetModuleHandleA(mod_name_str.as_ptr());
        }

        if module == ptr::null_mut() {
            return None;
        }

        let function_name: CString = CString::new(function_name).expect("Failed to create CString");

        let addr = GetProcAddress(module, function_name.as_ptr()) as usize;
        if addr == 0 {
            return None;
        }

        Some(addr as usize)
    }
}

/// Get the address of a module.
#[cfg(target_os = "windows")]
pub fn get_module_address(module_name: &str) -> Option<usize> {
    use crate::misc::get_address_range_for_module;
    use crate::modules::AddressRange;

    let module_range: Option<AddressRange> = get_address_range_for_module(module_name);

    if module_range.is_some() {
        return Some(module_range.unwrap().start as usize);
    }

    None
}

/// Get the address of the main module.
#[cfg(target_os = "windows")]
pub fn get_main_module_address() -> Option<usize> {
    let mut mod_name: [u8; 260] = [0; MAX_PATH];
    let own_process_handle = usize::MAX as HANDLE;
    unsafe {
        let res = GetModuleBaseNameA(
            own_process_handle,
            null_mut(),
            mod_name.as_mut_ptr() as *mut i8,
            MAX_PATH as u32,
        );
        if res == 0 {
            error!("Failed to GetModuleBaseNameA");
            return None;
        }

        let mod_name_len = mod_name.iter().position(|&r| r == 0).unwrap();
        let mod_name_str = std::str::from_utf8(&mod_name[0..mod_name_len]).unwrap();

        get_module_address(mod_name_str)
    }
}

/// Gets the entry point of the program from the main module.
#[cfg(target_os = "windows")]
pub fn get_program_entry_point() -> Option<usize> {
    use std::{ffi::CString, ptr::null_mut};

    use winapi::{
        shared::minwindef::MAX_PATH,
        um::{
            libloaderapi::GetModuleHandleA,
            psapi::{GetModuleBaseNameA, MODULEINFO},
            winnt::HANDLE,
        },
    };

    use crate::misc::get_module_info;

    let mut mod_name: [u8; 260] = [0; MAX_PATH];
    let own_process_handle = usize::MAX as HANDLE;
    unsafe {
        let res = GetModuleBaseNameA(
            own_process_handle,
            null_mut(),
            mod_name.as_mut_ptr() as *mut i8,
            MAX_PATH as u32,
        );
        if res == 0 {
            error!("Failed to GetModuleBaseNameA");
            return None;
        }

        let mod_name_len = mod_name.iter().position(|&r| r == 0).unwrap();
        let mod_name_str = std::str::from_utf8(&mod_name[0..mod_name_len]).unwrap();

        let mod_name_str: CString = CString::new(mod_name_str).expect("Failed to create CString");

        let module = GetModuleHandleA(mod_name_str.as_ptr());

        let module_info: Option<MODULEINFO> = get_module_info(module);
        module_info?;

        let module_info = module_info.unwrap();

        Some(module_info.EntryPoint as usize)
    }
}
