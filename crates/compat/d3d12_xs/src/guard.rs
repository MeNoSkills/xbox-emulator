use core::cell::Cell;
use core::ffi::c_void;
use std::sync::Once;

#[repr(C)]
struct Frame {
    rsp: usize,
    resume: usize,
}

thread_local! {
    static ACTIVE: Cell<*mut Frame> = const { Cell::new(core::ptr::null_mut()) };
}

extern "system" {
    fn AddVectoredExceptionHandler(first: u32, handler: unsafe extern "system" fn(*mut [usize; 2]) -> i32) -> *mut c_void;
}

extern "C" {
    fn tb_guard_enter(f: unsafe extern "C" fn(*mut c_void), ctx: *mut c_void, frame: *mut Frame) -> u32;
}

core::arch::global_asm!(
    ".text",
    ".globl tb_guard_enter",
    "tb_guard_enter:",
    "push rbp",
    "push rbx",
    "push rdi",
    "push rsi",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "sub rsp, 200",
    "movaps [rsp + 32], xmm6",
    "movaps [rsp + 48], xmm7",
    "movaps [rsp + 64], xmm8",
    "movaps [rsp + 80], xmm9",
    "movaps [rsp + 96], xmm10",
    "movaps [rsp + 112], xmm11",
    "movaps [rsp + 128], xmm12",
    "movaps [rsp + 144], xmm13",
    "movaps [rsp + 160], xmm14",
    "movaps [rsp + 176], xmm15",
    "mov [r8], rsp",
    "lea rax, [rip + tb_guard_resume]",
    "mov [r8 + 8], rax",
    "mov rax, rcx",
    "mov rcx, rdx",
    "call rax",
    "mov eax, 1",
    "tb_guard_done:",
    "movaps xmm6, [rsp + 32]",
    "movaps xmm7, [rsp + 48]",
    "movaps xmm8, [rsp + 64]",
    "movaps xmm9, [rsp + 80]",
    "movaps xmm10, [rsp + 96]",
    "movaps xmm11, [rsp + 112]",
    "movaps xmm12, [rsp + 128]",
    "movaps xmm13, [rsp + 144]",
    "movaps xmm14, [rsp + 160]",
    "movaps xmm15, [rsp + 176]",
    "add rsp, 200",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rsi",
    "pop rdi",
    "pop rbx",
    "pop rbp",
    "ret",
    "tb_guard_resume:",
    "xor eax, eax",
    "jmp tb_guard_done",
);

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_IN_PAGE_ERROR: u32 = 0xC000_0006;
const CONTEXT_RSP: usize = 0x98;
const CONTEXT_RIP: usize = 0xF8;
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

unsafe extern "system" fn handler(info: *mut [usize; 2]) -> i32 {
    let code = *((*info)[0] as *const u32);
    if code != STATUS_ACCESS_VIOLATION && code != STATUS_IN_PAGE_ERROR {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let frame = ACTIVE.with(|a| a.get());
    if frame.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let ctx = (*info)[1] as *mut u8;
    *(ctx.add(CONTEXT_RSP) as *mut usize) = (*frame).rsp;
    *(ctx.add(CONTEXT_RIP) as *mut usize) = (*frame).resume;
    EXCEPTION_CONTINUE_EXECUTION
}

fn install() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| unsafe {
        AddVectoredExceptionHandler(1, handler);
    });
}

struct Call<F, R> {
    f: Option<F>,
    out: Option<R>,
}

unsafe extern "C" fn trampoline<F: FnOnce() -> R, R>(ctx: *mut c_void) {
    let call = &mut *(ctx as *mut Call<F, R>);
    if let Some(f) = call.f.take() {
        call.out = Some(f());
    }
}

pub fn guarded<F: FnOnce() -> R, R>(f: F) -> Option<R> {
    install();
    let mut call = Call { f: Some(f), out: None };
    let mut frame = Frame { rsp: 0, resume: 0 };
    let prev = ACTIVE.with(|a| a.replace(&mut frame));
    let ok = unsafe { tb_guard_enter(trampoline::<F, R>, &mut call as *mut _ as *mut c_void, &mut frame) };
    ACTIVE.with(|a| a.set(prev));
    if ok != 0 {
        call.out
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    extern "system" {
        fn VirtualAlloc(addr: *mut c_void, len: usize, ty: u32, protect: u32) -> *mut c_void;
        fn VirtualFree(addr: *mut c_void, len: usize, ty: u32) -> i32;
    }

    const PAGE: usize = 4096;

    unsafe fn decommitted_page() -> usize {
        let base = VirtualAlloc(core::ptr::null_mut(), 3 * PAGE, 0x3000, 0x04) as usize;
        assert_ne!(base, 0);
        core::ptr::write_bytes(base as *mut u8, 0xab, 3 * PAGE);
        assert_eq!(VirtualFree((base + PAGE) as *mut c_void, PAGE, 0x4000), 1);
        base
    }

    #[test]
    fn returns_the_closure_value_when_nothing_faults() {
        let v = vec![1u32, 2, 3];
        assert_eq!(guarded(|| v.iter().sum::<u32>()), Some(6));
    }

    #[test]
    fn a_read_of_decommitted_memory_returns_none_instead_of_crashing() {
        unsafe {
            let base = decommitted_page();
            let read = |off: usize, len: usize| guarded(|| core::slice::from_raw_parts((base + off) as *const u8, len).iter().map(|&b| b as u64).sum::<u64>());
            assert_eq!(read(0, PAGE), Some(0xab * PAGE as u64));
            assert_eq!(read(PAGE, PAGE), None);
            assert_eq!(read(0, 3 * PAGE), None);
            assert_eq!(read(2 * PAGE, PAGE), Some(0xab * PAGE as u64));
            VirtualFree(base as *mut c_void, 0, 0x8000);
        }
    }

    #[test]
    fn guards_nest_and_the_outer_one_still_catches_after_the_inner_returns() {
        unsafe {
            let base = decommitted_page();
            let touch = || core::ptr::read_volatile((base + PAGE) as *const u8);
            let outer = guarded(|| {
                let inner = guarded(touch);
                assert_eq!(inner, None);
                touch()
            });
            assert_eq!(outer, None);
            assert_eq!(guarded(|| 7), Some(7));
            VirtualFree(base as *mut c_void, 0, 0x8000);
        }
    }

    #[test]
    fn nonvolatile_registers_survive_a_fault() {
        unsafe {
            let base = decommitted_page();
            let mut acc = 0u64;
            for i in 0..1000u64 {
                acc = acc.wrapping_add(i);
                let hit = guarded(|| core::ptr::read_volatile((base + PAGE) as *const u8));
                assert_eq!(hit, None);
                let ok = guarded(|| core::ptr::read_volatile(base as *const u8));
                assert_eq!(ok, Some(0xab));
            }
            assert_eq!(acc, 499500);
            VirtualFree(base as *mut c_void, 0, 0x8000);
        }
    }

    #[test]
    fn a_thread_decommitting_concurrently_never_crashes_the_reader() {
        unsafe {
            let base = VirtualAlloc(core::ptr::null_mut(), 64 * PAGE, 0x3000, 0x04) as usize;
            assert_ne!(base, 0);
            let stop = std::sync::atomic::AtomicBool::new(false);
            let (mut ok, mut failed) = (0u32, 0u32);
            std::thread::scope(|s| {
                s.spawn(|| {
                    let mut i = 0usize;
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        let page = (base + (i % 64) * PAGE) as *mut c_void;
                        VirtualFree(page, PAGE, 0x4000);
                        VirtualAlloc(page, PAGE, 0x1000, 0x04);
                        i += 1;
                    }
                });
                for _ in 0..20000 {
                    match guarded(|| core::slice::from_raw_parts(base as *const u8, 64 * PAGE).iter().fold(0u64, |a, &b| a.wrapping_add(b as u64))) {
                        Some(_) => ok += 1,
                        None => failed += 1,
                    }
                }
                stop.store(true, std::sync::atomic::Ordering::Relaxed);
            });
            eprintln!("concurrent decommit: {ok} reads completed, {failed} faulted and were skipped");
            assert_eq!(ok + failed, 20000);
            VirtualFree(base as *mut c_void, 0, 0x8000);
        }
    }

    #[test]
    fn unrelated_exceptions_are_left_alone_and_the_guard_is_cleared_afterwards() {
        assert!(ACTIVE.with(|a| a.get()).is_null());
        let _ = guarded(|| 1);
        assert!(ACTIVE.with(|a| a.get()).is_null());
    }
}
