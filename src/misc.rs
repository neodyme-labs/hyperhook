//! A collection of miscellaneous utility functions and error handling code used in various parts of the HyperHook library.

#[cfg(unix)]
use libc::*;
#[cfg(unix)]
use nix::sys::signal;
#[cfg(unix)]
use phdrs::objects;
#[cfg(unix)]
use std::alloc::{alloc, Layout};


#[cfg(windows)]
use winapi::shared::minwindef::HMODULE;

#[cfg(windows)]
use winapi::um::{
    processthreadsapi::GetCurrentProcess,
    errhandlingapi::GetLastError,
    winbase::SetProcessWorkingSetSize,
    memoryapi::{VirtualAlloc, VirtualLock},
    psapi::MODULEINFO,
};

use std::panic;

use log::*;

use crate::modules;
use crate::nyx;

/// Allocates memory pages and locks them in memory to make them resident
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
pub fn malloc_resident_pages(num_pages: usize) -> Option<usize> {
    // Get pagesize
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };

    let data_size = page_size * num_pages;

    // Allocate a page-aligned memory block
    let layout = Layout::from_size_align(data_size, page_size).unwrap();
    let aligned_ptr = unsafe { alloc(layout) };

    if aligned_ptr.is_null() {
        error!("Failed to allocate memory");
        return None;
    }

    info!("Allocated memory at address: {:?}", aligned_ptr);

    // Lock the pages in memory to prevent swapping (resident pages)
    let result = unsafe { libc::mlock(aligned_ptr as *const libc::c_void, data_size) };
    if result != 0 {
        error!("Failed to lock pages in memory");
        return None;
    }

    info!("Locked memory at address: {:?}", aligned_ptr);

    Some(aligned_ptr as uintptr_t)
}

#[cfg(target_os = "windows")]
#[inline(never)]
pub fn malloc_resident_pages(num_pages: usize) -> Option<usize> {
    use std::ptr::null_mut;

    use winapi::ctypes::c_void;
    // Get pagesize
    let page_size = 0x1000; // Hardcoded for now. Windows supports 4k (small) and 2MB pages
    let dw_min = 1 << 25; // min: 64MB
    let dw_max = 1 << 31; // max: 2GB

    let data_size = page_size * num_pages;

    // Allocate actual memory as RW
    // 0x3000 = MEM_RESERVE | MEM_COMMIT 0x04 = PAGE_READWRITE
    let alloc = unsafe {
        VirtualAlloc(null_mut(), data_size, 0x3000, 0x04) as *mut c_void
    };

    if alloc.is_null() {
        let last_error = unsafe { GetLastError() };
        error!("Failed to allocate memory. Last Error: {}", last_error);
        return None;
    }

    let h_process;
    unsafe {
        h_process = GetCurrentProcess();
    }

    if h_process.is_null() {
        let last_error = unsafe { GetLastError() };
        error!("Failed to open own process. Last Error: {}", last_error);
        return None;
    }

    
    /*
    let mut dw_min: SIZE_T = 0;
    let mut dw_max: SIZE_T = 0;
    unsafe {
        if GetProcessWorkingSetSize(h_process, &mut dw_min, &mut dw_max) == 0 {
            let last_error = GetLastError();
            error!("Failed to get process working set size. Last Error: {}", last_error);
            return None;
        }
    }
    */

    unsafe {
        if SetProcessWorkingSetSize(h_process, dw_min, dw_max) == 0 {
            let last_error = GetLastError();
            error!("Failed to set process working set size. Last Error: {}", last_error);
            return None;
        }
    }

    unsafe {
        if VirtualLock(alloc as *mut c_void, data_size) == 0 {
            let last_error = GetLastError();
            error!(
                "[+] WARNING: Virtuallock failed to lock payload buffer. Last Error: {}",
                last_error
            );
            return None;
        }
    }

    Some(alloc as usize)
}

#[cfg(all(target_arch = "x86", target_os = "linux"))]
extern "C" fn sighandler_default(
    signo: libc::c_int,
    info: *mut libc::siginfo_t,
    extra: *mut libc::c_void,
) {
    let ucontext_ptr: *mut ucontext_t = extra as *mut libc::ucontext_t;
    let ucontext: &mut libc::ucontext_t = unsafe { &mut *ucontext_ptr };

    let signinfo_ptr: *mut siginfo_t = info as *mut libc::siginfo_t;
    let siginfo: &mut siginfo_t = unsafe { &mut *signinfo_ptr };

    let reason: u64 = 0x8000000000000000u64
        | ucontext.uc_mcontext.gregs[libc::REG_EIP as usize] as u64
        | ((siginfo.si_signo as u64) << 47);

    nyx::hypercall(nyx::KAFLHypercalls::Panic, reason as usize);

    panic!("Caught fatal signal: {signo}")
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
extern "C" fn sighandler_default(
    signo: libc::c_int,
    info: *mut libc::siginfo_t,
    extra: *mut libc::c_void,
) {
    let ucontext_ptr: *mut ucontext_t = extra as *mut libc::ucontext_t;
    let ucontext: &mut libc::ucontext_t = unsafe { &mut *ucontext_ptr };

    let signinfo_ptr: *mut siginfo_t = info;
    let siginfo: &mut siginfo_t = unsafe { &mut *signinfo_ptr };

    let reason: u64 = 0x8000000000000000u64
        | ucontext.uc_mcontext.gregs[libc::REG_RIP as usize] as u64
        | ((siginfo.si_signo as u64) << 47);

    nyx::hypercall(nyx::KAFLHypercalls::Panic, reason as usize);

    panic!("Caught fatal signal: {signo}")
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
pub extern "C" fn sighandler_backtrace(
    signo: libc::c_int,
    _info: *mut libc::siginfo_t,
    _extra: *mut libc::c_void,
) {
    use std::backtrace::Backtrace;
    let bp = Backtrace::force_capture().to_string();
    nyx::panic_extended(bp);

    panic!("Caught fatal signal: {signo}")
}

#[cfg(all(target_arch = "x86", target_os = "windows"))]
#[inline(never)]
unsafe extern "system" fn exception_handler_default(
    exception: *mut winapi::um::winnt::EXCEPTION_POINTERS,
) -> winapi::um::winnt::LONG {
    let exception_data = *exception;
    let exception_record = *exception_data.ExceptionRecord;
    let exception_context = *exception_data.ContextRecord;

    let reason: u64 = 0x8000000000000000u64
        | exception_context.Eip as u64
        | ((exception_record.ExceptionCode as u64) << 47);

    nyx::hypercall(nyx::KAFLHypercalls::Panic, reason as usize);

    let exception_code = exception_record.ExceptionCode;
    let addr = exception_record.ExceptionAddress as usize;

    panic!("Caught fatal, unhanlded exception: {exception_code:016x} Addr: {addr:016x}")
}

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
#[inline(never)]
unsafe extern "system" fn exception_handler_default(
    exception: *mut winapi::um::winnt::EXCEPTION_POINTERS,
) -> winapi::um::winnt::LONG {
    use winapi::um::errhandlingapi::GetLastError;

    let last_error = GetLastError();
    error!("Exception Handler Error: {last_error}");
    let exception_data = *exception;
    let exception_record = *exception_data.ExceptionRecord;
    let exception_context = *exception_data.ContextRecord;

    let reason: u64 = 0x8000000000000000u64
        | exception_context.Rip
        | ((exception_record.ExceptionCode as u64) << 47);

    nyx::hypercall(nyx::KAFLHypercalls::Panic, reason as usize);

    let exception_code = exception_record.ExceptionCode;
    let addr = exception_record.ExceptionAddress as usize;

    panic!("Caught fatal, unhanlded exception: {exception_code:016x} Addr: {addr:016x}")
}

/// Register custom signal handlers on Unix systems and exception handlers on Windows systems.
#[cfg(unix)]
pub fn register_sighandlers_custom(
    handler: extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void),
) {
    unsafe {
        let sig_action: signal::SigAction = signal::SigAction::new(
            signal::SigHandler::SigAction(handler),
            signal::SaFlags::empty(),
            signal::SigSet::empty(),
        );
        if signal::sigaction(signal::SIGSEGV, &sig_action).is_err()
            || signal::sigaction(signal::SIGFPE, &sig_action).is_err()
            || signal::sigaction(signal::SIGBUS, &sig_action).is_err()
            || signal::sigaction(signal::SIGILL, &sig_action).is_err()
            || signal::sigaction(signal::SIGABRT, &sig_action).is_err()
            || signal::sigaction(signal::SIGIOT, &sig_action).is_err()
            || signal::sigaction(signal::SIGTRAP, &sig_action).is_err()
            || signal::sigaction(signal::SIGSYS, &sig_action).is_err()
        {
            panic!("Failed to installed at least one signal handler. Aborting...");
        }
    };
}

#[cfg(windows)]
#[inline(never)]
pub fn register_sighandlers_custom(
    handler: winapi::um::errhandlingapi::LPTOP_LEVEL_EXCEPTION_FILTER,
) {
    use winapi::um::errhandlingapi::SetUnhandledExceptionFilter;
    unsafe {
        SetUnhandledExceptionFilter(handler);
    };
}

/// Gets memory range for n modules by name and sets them as PT ranges.
#[inline(never)]
pub fn setup_pt_ranges(modules: Vec<String>) {
    for m in modules {
        let range = get_address_range_for_module(m.as_str());
        match range {
            Some(address_range) => nyx::send_pt_range_to_hypervisor(address_range),
            None => warn!("[!] Module not found for tracing: {m}"),
        }
    }
}

#[cfg(windows)]
pub fn get_module_info(h_module: HMODULE) -> Option<MODULEINFO> {
    use std::mem;

    use winapi::um::{
            psapi::{GetModuleInformation, MODULEINFO},
            winnt::HANDLE,
        };

    let mut mod_info: MODULEINFO = MODULEINFO {
        lpBaseOfDll: std::ptr::null_mut(),
        SizeOfImage: 0,
        EntryPoint: std::ptr::null_mut(),
    };
    let own_process_handle = usize::MAX as HANDLE; // -1 is the own process pseudo handle
    unsafe {
        if GetModuleInformation(
            own_process_handle,
            h_module,
            &mut mod_info,
            mem::size_of::<MODULEINFO>() as u32,
        ) == 0
        {
            return None;
        }
    }

    Some(mod_info)
}

#[cfg(windows)]
pub fn get_address_range_for_module(module: &str) -> Option<modules::AddressRange> {
    use std::mem;

    use winapi::{
        shared::{
            minwindef::{DWORD, HINSTANCE, HMODULE, MAX_PATH},
            ntdef::NULL,
        },
        um::{
            errhandlingapi::GetLastError,
            psapi::GetModuleBaseNameA,
            winnt::HANDLE,
        },
    };

    trace!("Searching for module: {}", module);

    let mut mods = [NULL as HINSTANCE; 1024];
    let own_process_handle = usize::MAX as HANDLE; // -1 is the own process pseudo handle
    let mut space_needed: DWORD = 0;

    {
        unsafe {
            let res = winapi::um::psapi::EnumProcessModules(
                own_process_handle,
                mods.as_mut_ptr(),
                mem::size_of::<[HMODULE; 1024]>() as u32,
                &mut space_needed,
            );

            if res == 0 {
                let last_error = GetLastError();

                error!("EnumProcessModules failed. Res: {res} Error: {last_error}");
            }
            trace!(
                "EnumProcessModules returned {} elements",
                space_needed / std::mem::size_of::<HANDLE>() as u32
            )
        }
    }

    for i in 0..space_needed / mem::size_of::<HMODULE>() as u32 {
        //Get module names
        let mut mod_name: [u8; 260] = [0; MAX_PATH];
        let res: DWORD;
        unsafe {
            res = GetModuleBaseNameA(
                own_process_handle,
                mods[i as usize],
                mod_name.as_mut_ptr() as *mut i8,
                MAX_PATH as u32,
            );
            trace!("GetModuleBaseNameA res: {}", res);
            if res != 0 {
                let mod_name_len = mod_name.iter().position(|&r| r == 0).unwrap();
                let mod_name_str = std::str::from_utf8(&mod_name[0..mod_name_len]).unwrap();

                trace!("Found loaded module: {}", mod_name_str);

                if mod_name_str.contains(module) {
                    let mod_info = get_module_info(mods[i as usize]);
                    mod_info?;
                    let mod_info = mod_info.unwrap();

                    let addr_range = modules::AddressRange {
                        start: mod_info.lpBaseOfDll as u64,
                        end: (mod_info.lpBaseOfDll as u64 + mod_info.SizeOfImage as u64) as u64,
                        ..Default::default()
                    };

                    trace!(
                        "Found matching module. Base: {:016x} End: {:016x}",
                        addr_range.start,
                        addr_range.end
                    );
                    return Some(addr_range);
                }
            }
        }
    }

    None
}

#[cfg(unix)]
#[inline(never)]
pub fn get_address_range_for_module(module: &str) -> Option<modules::AddressRange> {
    trace!("Searching for module: {}", module);

    for o in objects() {
        let obj_name_str = String::from_utf8_lossy(o.name().to_bytes()).to_string();

        if obj_name_str.contains(module) {
            let base_addr = o.addr();

            for h in o.iter_phdrs() {
                if (h.type_() & PT_LOAD) != 0 && (h.flags() & PF_X) != 0 {
                    let range = modules::AddressRange {
                        start: (base_addr + h.vaddr()),
                        end: (base_addr + h.offset() + h.memsz()),
                        ..Default::default()
                    };
                    trace!("Module found: \n\tRange: {:x?}", range);
                    return Some(range);
                }
            }
        }
    }

    info!("Module {} not found!", module);
    None
}

/// The `sighandler_default`/`exception_handler_default` methods as the default custom handlers.
#[cfg(unix)]
pub fn register_sighandlers_default() {
    register_sighandlers_custom(sighandler_default)
}

#[cfg(windows)]
pub fn register_sighandlers_default() {
    register_sighandlers_custom(Some(exception_handler_default))
}
