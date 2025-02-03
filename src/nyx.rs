//! Module containing Nyx-related definitions, constants, and functions.

#[cfg(target_arch = "x86")]
use core::arch::x86::__cpuid_count;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::__cpuid_count;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::CpuidResult;

#[cfg(target_arch = "x86")]
use std::arch::x86::CpuidResult;

#[cfg(all(feature = "pt", feature = "kafl"))]
use std::arch::asm;

use crate::modules;
use log::*;
use std::ffi::CString;

const HYPERTRASH_HYPERCALL_MASK: u32 = 0xAA000000;

#[cfg(all(feature = "pt", feature = "kafl"))]
const HYPERCALL_RAX_PT: u32 = 0x01f;

#[cfg(not(feature = "pt"))]
const HYPERCALL_RAX_VMWARE: u32 = 0x8080801f;
const CPU_ID_VENDOR: u32 = 0x80000004;

/// Magic bytes that identify Nyx-QEMU
pub const NYX_HOST_MAGIC: u32 = 0x4878794e;
/// Magic bytes that identify Nyx agents
pub const NYX_AGENT_MAGIC: u32 = 0x4178794e;

/// Expected Nyx host version
pub const NYX_HOST_VERSION: u32 = 2;
/// Nyx agent version sent to the host
pub const NYX_AGENT_VERSION: u32 = 1;

#[cfg(not(feature = "pt"))]
const VMWARE_PORT: u32 = 0x5658;

/// Defines the maximum payload size
pub const PAYLOAD_MAX_SIZE: u32 = 1024 * 1024;

/// Implements the `log::Log` trait, providing logging functionality using the `log` crate.
/// It formats log records and sends them to Nyx via `hprintf`.
#[repr(packed)]
pub struct NyxLogger;

impl log::Log for NyxLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            hprintf(format!("{} - {} \n", record.level(), record.args()));
        }
    }

    fn flush(&self) {}
}

/// Holds the size and a pointer to a payload.
#[repr(C)]
pub struct KAFLPayload {
    pub size: u32,
    pub data: *const u8,
}

impl KAFLPayload {
    /// Creates a `KAFLPayload` reference from a raw pointer
    /// # Safety
    /// This function is unsafe because it assumes the pointer is valid and properly aligned.
    pub unsafe fn from_raw(raw_ptr: *const usize) -> KAFLPayload {
        let size = unsafe { std::ptr::read(*raw_ptr as *const u32) };
        let data: *const u8 = (*raw_ptr + std::mem::size_of::<u32>()) as *const u8;

        KAFLPayload { size, data }
    }
}

// #[repr(C)]
// pub struct KAFLRanges {
//     pub ip: [u64; 4],
//     pub size: [u64; 4],
//     pub enabled: [u8; 4],
// }

/// Nyx host configuration.
#[derive(Default)]
#[repr(packed)]
pub struct HostConfig {
    pub host_magic: u32,
    pub host_version: u32,
    pub bitmap_size: u32,
    pub ijon_bitmap_size: u32,
    pub payload_buffer_size: u32,
    pub worker_id: u32,
}

/// Nyx agent configuration.
#[derive(Default)]
#[repr(packed)]
pub struct AgentConfig {
    pub agent_magic: u32,
    pub agent_version: u32,
    pub agent_timeout_detection: u8,
    pub agent_tracing: u8,
    pub agent_ijon_tracing: u8,
    pub agent_non_reload_mode: u8,
    pub trace_buffer_vaddr: u64,
    pub ijon_trace_buffer_vaddr: u64,
    pub coverage_bitmap_size: u32,
    pub input_buffer_size: u32,
    pub dump_payloads: u8,
}

/// Represents a dump file which can be send to the Nyx host.
#[repr(C)]
pub struct DumpFile {
    pub file_name_str_ptr: u64,
    pub data_ptr: u64,
    pub bytes: u64,
    pub append: u8,
}

/// Nyx CPU types.
pub enum NxyCpuType {
    Unknown = 0,
    NyxCpuV1 = 1, /* Nyx CPU used by KVM-PT */
    NyxCpuV2 = 2, /* Nyx CPU used by vanilla KVM + VMWare backdoor */
}

/// Nyx hypercalls to communicate with the Nyx host
#[repr(u32)]
#[derive(Debug)]
pub enum KAFLHypercalls {
    Acquire = 0,
    GetPayload = 1,
    /* deprecated */
    GetProgram = 2,
    /* deprecated */
    GetArgv = 3,

    Release = 4,
    SubmitCR3 = 5,
    SubmitPanic = 6,

    /* deprecated */
    SubmitKASAN = 7,
    Panic = 8,
    /* deprecated */
    KASAN = 9,
    Lock = 10,

    /* deprecated */
    Info = 11,

    NextPayload = 12,
    Printf = 13,
    /* deprecated */
    PrintkAddr = 14,
    /* deprecated */
    Printk = 15,

    /* user space only hypercalls */
    UserRangeAdvise = 16,
    UserSubmitMode = 17,
    UserFastAcquire = 18,

    /* 19 is already used for exit reason KVM_EXIT_KAFL_TOPA_MAIN_FULL */
    UserAbort = 20,
    RangeSubmit = 29,
    ReqStreamData = 30,
    PanicExtended = 32,

    CreateTmpSnapshot = 33,
    /* hypercall for debugging / development purposes */
    DebugTmpSnapshot = 34,
    GetHostConfig = 35,
    SetAgentConfig = 36,
    DumpFile = 37,
    ReqStreamDataBulk = 38,
    PersistPagePastSnapshot = 39,
}

#[repr(u32)]
pub enum KAFLHypertrashCalls {
    Prepare = HYPERTRASH_HYPERCALL_MASK,
    Config = (1u32 | HYPERTRASH_HYPERCALL_MASK),
    Acquire = (2u32 | HYPERTRASH_HYPERCALL_MASK),
    Release = (3u32 | HYPERTRASH_HYPERCALL_MASK),
    HPrintf = (4u32 | HYPERTRASH_HYPERCALL_MASK),
}

/// Represents different modes (64-bit, 32-bit, 16-bit) available in Nyx.
#[repr(u32)]
pub enum KAFLMode {
    Bits64 = 0,
    Bits32 = 1,
    Bits16 = 2,
}

/// Explicitly tell the host if the target is 32 or 64 bit code.
#[cfg(target_arch = "x86_64")]
pub fn submit_mode() {
    hypercall(KAFLHypercalls::UserSubmitMode, KAFLMode::Bits64 as usize);
}

#[cfg(target_arch = "x86")]
pub fn submit_mode() {
    hypercall(KAFLHypercalls::UserSubmitMode, KAFLMode::Bits32 as usize);
}

/// Like printf, but using the KAFL_HYPERCALL_PRINTF as printing backend.
pub fn hprintf(data: String) {
    let c_string: &'static CString = Box::leak(Box::new(
        CString::new(data).expect("Failed to create CString"),
    ));
    hypercall(KAFLHypercalls::Printf, c_string.as_ptr() as usize);
}

/// Signal a fatal error to Nyx.
pub fn habort(data: String) {
    hypercall(KAFLHypercalls::UserAbort, data.as_ptr() as usize);
}

/// Tell Nyx where to write the payload by providing it the payload’s guest address.
pub fn get_payload(address: usize) {
    hypercall(KAFLHypercalls::GetPayload, address);
}

/// Mark the start and stop of a single execution.
pub fn user_acquire() {
    hypercall(KAFLHypercalls::Acquire, 0usize);
}

/// Signal that the execution is done with no errors.
pub fn release() {
    hypercall(KAFLHypercalls::Release, 0usize);
}

/// Trigger the actual write of the next payload into the previously registered buffer.
pub fn next_payload() {
    hypercall(KAFLHypercalls::NextPayload, 0usize);
}

/// Generate a VM pre-snapshot for the fuzzer.
pub fn lock() {
    hypercall(KAFLHypercalls::Lock, 0usize);
}

/// Initialize PT (Page Table) tracing ranges and notify the hypervisor about the address ranges to be traced.
#[inline(never)]
pub fn send_pt_range_to_hypervisor(range: modules::AddressRange) {
    // prevent compiler optimizations
    core::hint::black_box(&range);
    let range_box = Box::new(range);
    let range_ptr = Box::into_raw(range_box) as usize;

    hypercall(KAFLHypercalls::RangeSubmit, range_ptr);
}

/// Sends binary buffers that will be stored as files in $WORK_DIR/dump/.
pub fn dump_payload(buf: Vec<u8>, filename: String) {
    let dump_file = DumpFile {
        file_name_str_ptr: filename.as_ptr() as u64,
        data_ptr: buf.as_ptr() as u64,
        bytes: buf.len() as u64,
        append: 0,
    };

    hypercall(
        KAFLHypercalls::DumpFile,
        std::ptr::addr_of!(dump_file) as usize,
    );
}

/// Like KAFLHypercalls::Panic but with additional data
/// Use libnyx::NyxProcess aux_string() to receive the string on the host side
pub fn panic_extended(data: String) {
    let c_string: &'static CString = Box::leak(Box::new(
        CString::new(data).expect("Failed to create CString"),
    ));
    hypercall(KAFLHypercalls::PanicExtended, c_string.as_ptr() as usize);
}

/// Initialize the Nyx agent, sets up panic handlers, and sets up the NyxLogger based on the verbosity level specified.
pub fn agent_init(verbose: bool) {
    // Register panic handler in case something crashes in the harness (only PT and kafl)
    #[cfg(all(feature = "pt", feature = "kafl"))]
    std::panic::set_hook(Box::new(|panic_info| {
        hprintf(format!("Panic in harness: {}", panic_info));
        habort(format!("Panic in harness: {}", panic_info));

        loop {}
    }));

    // Initial handshake
    hypercall(KAFLHypercalls::Acquire, 0usize);
    hypercall(KAFLHypercalls::Release, 0usize);

    let mut host_config = HostConfig {
        ..Default::default()
    };

    hypercall(
        KAFLHypercalls::GetHostConfig,
        std::ptr::addr_of_mut!(host_config) as usize,
    );

    if host_config.host_magic != NYX_HOST_MAGIC {
        habort(format!(
            "HOST_MAGIC mismatch! {:016x} != {:016x}",
            unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(host_config.host_magic)) },
            NYX_HOST_MAGIC
        ));
    }

    if unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(host_config.host_version)) }
        != NYX_HOST_VERSION
    {
        habort(format!(
            "HOST_VERSION mismatch! {:016x} != {:016x}",
            unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(host_config.host_version)) },
            NYX_HOST_VERSION
        ));
    }

    if host_config.payload_buffer_size > PAYLOAD_MAX_SIZE {
        habort(format!(
            "Payload size to large! {:016x} >  {:016x}",
            unsafe {
                std::ptr::read_unaligned(std::ptr::addr_of!(host_config.payload_buffer_size))
            },
            PAYLOAD_MAX_SIZE
        ));
    }

    let mut agent_config = AgentConfig {
        agent_magic: NYX_AGENT_MAGIC,
        agent_version: NYX_AGENT_VERSION,
        coverage_bitmap_size: host_config.bitmap_size,
        ..Default::default()
    };

    hypercall(
        KAFLHypercalls::SetAgentConfig,
        std::ptr::addr_of_mut!(agent_config.agent_magic) as usize,
    );

    hypercall(KAFLHypercalls::SubmitCR3, 0usize);
    submit_mode();

    // Initialize NyxLogger
    // hprints before agent initialization would result in segfault
    if verbose {
        let _ = log::set_boxed_logger(Box::new(NyxLogger))
            .map(|()| log::set_max_level(LevelFilter::Trace));
    } else {
        let _ = log::set_boxed_logger(Box::new(NyxLogger))
            .map(|()| log::set_max_level(LevelFilter::Warn));
    }

    trace!("Agent initialized");
}

/// Send a hypercall to the host.
#[cfg(not(feature = "kafl"))]
pub fn hypercall(hypercall: KAFLHypercalls, argument: usize) -> usize {
    warn!("Would do hypercall, but no kAFL Kernel: {hypercall:?} Arg: {argument:x?}");
    0
}

#[inline(never)]
#[cfg(all(target_arch = "x86_64", feature = "pt", feature = "kafl"))]
pub fn hypercall(hypercall: KAFLHypercalls, argument: usize) -> usize {
    let result: usize = 0;
    unsafe {
        asm!(
            "mov rax, {HYPERCALL_RAX:r}",
            "mov rbx, {hypercall:r}",
            "mov rcx, {argument:r}",
            "vmcall;",
            "mov {result}, rax",
            HYPERCALL_RAX = in(reg) HYPERCALL_RAX_PT,
            hypercall = in(reg) hypercall as u32,
            argument = in(reg) argument,
            result = out(reg) _,
        )
    }
    result
}

#[inline(never)]
#[cfg(all(target_arch = "x86_64", not(feature = "pt"), feature = "kafl"))]
pub fn hypercall(hypercall: KAFLHypercalls, argument: usize) -> usize {
    let result: usize = 0;
    unsafe {
        asm!(
            "mov rax, {HYPERCALL_RAX:r}",
            "mov rbx, {hypercall:r}",
            "mov rcx, {argument:r}",
            "mov dx, {VMWARE_PORT}",
            "out dx, rax",
            "mov {result}, rax",
            HYPERCALL_RAX = in(reg) HYPERCALL_RAX_VMWARE,
            hypercall = in(reg) hypercall as u32,
            argument = in(reg) argument,
            VMWARE_PORT = in(reg) VMWARE_PORT,
            result = out(reg) _,
        )
    }
    result
}

#[inline(never)]
#[cfg(all(target_arch = "x86", feature = "pt", feature = "kafl"))]
pub fn hypercall(hypercall: KAFLHypercalls, argument: usize) -> usize {
    let result: usize = 0;
    unsafe {
        asm!(
            "mov eax, {HYPERCALL_RAX}",
            "mov ebx, {hypercall}",
            "mov ecx, {argument}",
            "vmcall;",
            "mov {result}, eax",
            HYPERCALL_RAX = in(reg) HYPERCALL_RAX_PT,
            hypercall = in(reg) hypercall as u32,
            argument = in(reg) argument,
            result = out(reg) _,
        )
    }
    result
}

#[inline(never)]
#[cfg(all(target_arch = "x86", not(feature = "pt"), feature = "kafl"))]
pub fn hypercall(hypercall: KAFLHypercalls, argument: usize) -> usize {
    let result: usize = 0;
    unsafe {
        asm!(
            "mov eax, {HYPERCALL_RAX:r}",
            "mov ebx, {hypercall:r}",
            "mov ecx, {argument:r}",
            "mov dx, {VMWARE_PORT}",
            "out dx, eax",
            "mov {result}, eax",
            HYPERCALL_RAX = in(reg) HYPERCALL_RAX_VMWARE,
            hypercall = in(reg) hypercall as u32,
            argument = in(reg) argument,
            VMWARE_PORT = in(reg) VMWARE_PORT,
            result = out(reg) _,
        )
    }
    result
}

/// Check if the current CPU is a Nyx vCPU.
pub fn is_nyx_vcpu() -> bool {
    unsafe {
        let result = __cpuid_count(CPU_ID_VENDOR, 0);
        let eax: u32 = result.eax;
        let ebx = result.ebx;

        eax == 0x2058594e && ebx == 0x55504376 // = "NYX vCPU" in hex
    }
}

/// Get the type of the Nyx CPU.
pub fn get_nyx_cpu_type() -> NxyCpuType {
    unsafe {
        let result: CpuidResult = __cpuid_count(CPU_ID_VENDOR, 0);
        let eax: u32 = result.eax;
        let ebx: u32 = result.ebx;
        let ecx: u32 = result.ecx;
        let edx: u32 = result.edx;

        if eax != 0x2058594e || ebx != 0x55504376 {
            // = "NYX vCPU" in hex
            NxyCpuType::Unknown
        } else if ecx == 0x4f4e2820 && edx == 0x2954502d {
            // = " (NO-PT)" in hex
            NxyCpuType::NyxCpuV1
        } else {
            NxyCpuType::NyxCpuV2
        }
    }
}
