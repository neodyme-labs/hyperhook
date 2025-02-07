#![cfg(windows)]
use winapi::shared::minwindef;
use winapi::shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID};
extern crate hyperhook;
use std::mem;

use hyperhook::hooking;
use hyperhook::misc;
use hyperhook::modules;

use log::{error, info};
use simplelog::*;

const OFFSET_HOOK_ME: usize = 0x11900;
type FnHookMe1 = extern "C" fn(i32) -> i32;

#[inline(never)]
extern "C" fn hook_me_1_detour(x: i32) -> i32 {
    info!("In detour. Arg Original: {}", x);
    let mut hook_manager: std::sync::MutexGuard<'_, hooking::HookManager> =
        hooking::HOOK_MANAGER.lock().unwrap();
    info!("Calling original function with arg: 69420");
    unsafe {
        let orig_fn: FnHookMe1 = mem::transmute(hook_manager.get_trampoline("hook_me_1").unwrap());
        orig_fn(69420);
        694201337
    }
}

/// Entry point which will be called by the system once the DLL has been loaded
/// in the target process. Declaring this function is optional.
///
/// # Safety
///
/// What you can safely do inside here is very limited, see the Microsoft documentation
/// about "DllMain". Rust also doesn't officially support a "life before main()",
/// though it is unclear what that that means exactly for DllMain.
#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(dll_module: HINSTANCE, call_reason: DWORD, reserved: LPVOID) -> BOOL {
    const DLL_PROCESS_ATTACH: DWORD = 1;
    const DLL_PROCESS_DETACH: DWORD = 0;

    match call_reason {
        DLL_PROCESS_ATTACH => demo_init(), // Maybe: Start in thread
        DLL_PROCESS_DETACH => (),
        _ => (),
    }
    minwindef::TRUE
}

fn demo_init() {
    TermLogger::init(
        LevelFilter::Trace,
        ConfigBuilder::new()
            .set_level_padding(LevelPadding::Right)
            .build(),
        TerminalMode::Stdout,
        ColorChoice::Auto,
    )
    .unwrap();

    let module_entry_point = modules::get_program_entry_point();
    if module_entry_point.is_none() {
        error!("Could not find module entry point");
        return;
    }

    let module_entry_point = module_entry_point.unwrap();

    println!("Module EP VA: {:016x}", module_entry_point);
    let to_fuzz_base = modules::get_main_module_address().unwrap();
    unsafe {
        let mut hook_manager: std::sync::MutexGuard<'_, hooking::HookManager> =
            hooking::HOOK_MANAGER.lock().unwrap();
        hook_manager.add_raw_detour(
            "hook_me_1",
            (to_fuzz_base + OFFSET_HOOK_ME) as *const (),
            hook_me_1_detour as *const (),
        );
        hook_manager.enable_detour("hook_me_1");
    }

    misc::register_sighandlers_default();
    println!("Done!");
}
