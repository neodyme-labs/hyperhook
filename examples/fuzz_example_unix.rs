use log::trace;
use std::mem;
use std::sync::OnceLock;

#[cfg(not(feature = "pt"))]
use simplelog::*;

use hyperhook::*;

use redhook::*;

type FuzzCase = extern "C" fn(usize, i32) -> i32;
static PAYLOAD: OnceLock<usize> = OnceLock::new();

extern "C" fn fuzz_case_detour(_p_data: usize, _len: i32) -> i32 {
    trace!("In fuzz_case_detour");

    // Generates pre-snapshot if run with ./qemu_tool.sh create_snapshot
    nyx::lock(); 

    trace!("Initialize agent");
    nyx::agent_init(true);

    trace!("Register default signal handlers");
    misc::register_sighandlers_default(); 

    let hook_manager: std::sync::MutexGuard<'_, hooking::HookManager> =
        hooking::HOOK_MANAGER.lock().unwrap();

    // trace!(
    //     "Initializing PT ranges for libs: {:?}",
    //     crate::config::get_pt_trace_libs()
    // );
    // misc::setup_pt_ranges(crate::config::get_pt_trace_libs());

    trace!("Setup Intel-PT ranges for main module"); 
    misc::setup_pt_ranges(vec!["".to_string()]);

    let orig_fn: FuzzCase = unsafe {
        mem::transmute(
            hook_manager
                .get_trampoline("fuzz_case")
                .expect("Failed to get trampoline"),
        )
    };
    trace!("Got trampoline to original fuzz_case at {:016x}", orig_fn as usize);

    trace!("Allocate resident pages");
    let pages = misc::malloc_resident_pages(256).expect("Failed allocating memory");
    let payload = PAYLOAD.get_or_init(|| pages);
    trace!("Got payload pages at {:x}", payload);

    trace!("Send payload address to Nyx");
    nyx::get_payload(*payload);

    trace!("Starting fuzzing loop");

    trace!("Get next fuzz input");
    // Nyx takes snapshot on first NextPayload hypercall.
    nyx::next_payload();

    trace!("Enable feedback collection");
    nyx::user_acquire();
    
    let kafl_payload = unsafe { nyx::KAFLPayload::from_raw(payload) };
    trace!("Got fuzz payload of size {:x} at {:?}", kafl_payload.size, kafl_payload.data);
    
    trace!("Call original fuzz_case");
    orig_fn(kafl_payload.data as usize, kafl_payload.size as i32);

    trace!("Done. Disable feedbalc collection");
    nyx::release();
    0
}

hook! {
    unsafe fn __libc_start_main(
        main: usize,
        argc: libc::c_int,
        argv: *const *const libc::c_char,
        init: usize,
        fini: usize,
        rtld_fini: usize,
        stack_end: *const libc::c_void
    ) -> libc::c_int => my_libc_start_main {

        #[cfg(not(feature = "pt"))]
        TermLogger::init(
            LevelFilter::Trace,
            Config::default(),
            TerminalMode::Stdout,
            ColorChoice::Auto,
        ).unwrap();

        trace!("In hooked __libc_start_main. Argc: {argc} Main: {:016x}", main as usize);

        trace!("Get symbol address of target function");
        let fuzz_case_addr = modules::get_symbol_address("", "fuzz_case").expect("Failed to get symbol address");
        trace!("Got fuzz_case base address: {:016x}", fuzz_case_addr);

        unsafe {
            let mut hook_manager = hooking::HOOK_MANAGER.lock().unwrap();
            
            trace!("Place hook at target function");
            hook_manager.add_raw_detour(
                "fuzz_case",
                (fuzz_case_addr) as *const (),
                fuzz_case_detour as *const (),
            );

            trace!("Enable hook for target function");
            hook_manager.enable_detour("fuzz_case");
        }

        let exit_code = real!(__libc_start_main)(main as *const () as usize, argc, argv, init, fini, rtld_fini, stack_end);

        return exit_code;
    }
}
