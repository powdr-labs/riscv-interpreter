//! Hash-fixture guest. Reads a 32-byte input via HINT_BUFFER, hashes it once
//! with KECCAK-256 and once with SHA-256, then reveals the two 32-byte
//! digests (keccak first at offset 0, sha256 at offset 32).

#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::panic::PanicInfo;

global_asm!(
    r#"
    .section .text._start
    .globl _start
_start:
    la sp, _stack_top
    call main
    .insn i 0x0b, 0, x0, x0, 0
    .section .bss
    .align 4
    .skip 4096
_stack_top:
    "#
);

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe {
        asm!(".insn i 0x0b, 0, x0, x0, 1", options(nostack, noreturn));
    }
}

#[inline(always)]
fn hint_input() {
    unsafe {
        asm!(".insn i 0x0b, 3, x0, x0, 0", options(nostack));
    }
}

#[inline(always)]
fn hint_storew(dst: *mut u32) {
    unsafe {
        asm!(".insn i 0x0b, 1, {0}, x0, 0", in(reg) dst, options(nostack));
    }
}

#[inline(always)]
fn hint_buffer(dst: *mut u32, len_words: u32) {
    unsafe {
        asm!(".insn i 0x0b, 1, {0}, {1}, 1", in(reg) dst, in(reg) len_words, options(nostack));
    }
}

#[inline(always)]
fn reveal(byte_offset: u32, value: u32) {
    unsafe {
        asm!(".insn i 0x0b, 2, {0}, {1}, 0", in(reg) byte_offset, in(reg) value, options(nostack));
    }
}

#[inline(always)]
fn keccak256(out: *mut u8, input: *const u8, len: u32) {
    unsafe {
        asm!(".insn r 0x0b, 4, 0, {0}, {1}, {2}", in(reg) out, in(reg) input, in(reg) len, options(nostack));
    }
}

#[inline(always)]
fn sha256(out: *mut u8, input: *const u8, len: u32) {
    unsafe {
        asm!(".insn r 0x0b, 4, 1, {0}, {1}, {2}", in(reg) out, in(reg) input, in(reg) len, options(nostack));
    }
}

#[inline(always)]
fn terminate() -> ! {
    unsafe {
        asm!(".insn i 0x0b, 0, x0, x0, 0", options(nostack, noreturn));
    }
}

#[no_mangle]
pub extern "C" fn main() -> ! {
    hint_input();
    let mut len_word: u32 = 0;
    hint_storew(&mut len_word as *mut u32); // discard length prefix
    let _ = len_word;
    let mut input: [u32; 8] = [0; 8];
    hint_buffer(input.as_mut_ptr(), 8);

    let mut keccak_out: [u32; 8] = [0; 8];
    let mut sha_out: [u32; 8] = [0; 8];
    keccak256(keccak_out.as_mut_ptr() as *mut u8, input.as_ptr() as *const u8, 32);
    sha256(sha_out.as_mut_ptr() as *mut u8, input.as_ptr() as *const u8, 32);

    for (i, w) in keccak_out.iter().enumerate() {
        reveal((i as u32) * 4, *w);
    }
    for (i, w) in sha_out.iter().enumerate() {
        reveal(32 + (i as u32) * 4, *w);
    }

    terminate();
}
