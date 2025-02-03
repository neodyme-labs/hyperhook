extern crate core;
use log::trace;
use std::mem;

use std::sync::OnceLock;

use hyperhook::*;

type FuzzCase = extern "C" fn(*const u8, i32) -> i32;

static PAYLOAD: OnceLock<usize> = OnceLock::new();
static INPUT_SIZE: usize = 1;

#[link(name = "fuzz_case", kind = "static")]
extern "C" {
    fn fuzz_case(data: *const u8, len: i32) -> i32;
}

extern "C" fn fuzz_case_detour(_p_data: *const u8, _len: i32) -> i32 {
    trace!("In fuzz_case detour");
    let hook_manager: std::sync::MutexGuard<'_, hooking::HookManager> =
        hooking::HOOK_MANAGER.lock().unwrap();

    trace!("Locked HOOK_MANAGER");

    let trampoline = hook_manager.get_trampoline("fuzz_case").unwrap();
    let orig_fn: FuzzCase = unsafe { std::mem::transmute::<_, FuzzCase>(trampoline) };

    trace!("fuzz_case address: {:x}", orig_fn as usize);

    trace!("Placed trampoline");

    let payload = PAYLOAD.get_or_init(|| {
        misc::malloc_resident_pages(INPUT_SIZE).expect("Failed to get payload address")
    });

    trace!("Payload pages {:x}", payload);

    trace!("Starting fuzzing loop");
    nyx::next_payload();
    nyx::user_acquire();

    let kafl_payload = unsafe { nyx::KAFLPayload::from_raw(payload) };

    trace!("payload size {:x}", kafl_payload.size);
    trace!("payload ptr {:x}", kafl_payload.data as usize);

    trace!("Calling orig fn");
    orig_fn(kafl_payload.data as *const u8, kafl_payload.size as i32);

    trace!("Called orig fn");
    nyx::release();

    trace!("Release");
    0
}

fn main() {
    trace!("Starting selffuzz");
    nyx::lock();

    nyx::agent_init(false);

    trace!("Finished Agent Init");

    misc::register_sighandlers_default();

    trace!("Get module base address");

    trace!("Get symbol address");
    let to_fuzz_addr =
        modules::get_symbol_address("", "fuzz_case").expect("Failed to get symbol address");

    misc::setup_pt_ranges(vec!["".to_string()]);

    trace!("Hooking target function");
    unsafe {
        let mut hook_manager: std::sync::MutexGuard<'_, hooking::HookManager> =
            hooking::HOOK_MANAGER.lock().unwrap();
        hook_manager.add_raw_detour(
            "fuzz_case",
            (to_fuzz_addr) as *const (),
            fuzz_case_detour as *const (),
        );
        hook_manager.enable_detour("fuzz_case");
    }

    trace!("Allocating resident pages");

    let pages = misc::malloc_resident_pages(INPUT_SIZE).expect("Failed allocating memory");

    let payload = PAYLOAD.get_or_init(|| pages);

    trace!("Allocated memory at address: {:x}", *payload);

    trace!("Mmap shared buffer between QEMU and fuzzer");
    nyx::get_payload(*payload);

    trace!("Calling fuzzcase");
    unsafe { fuzz_case(0 as *const u8, 0) };
}
