//! Minimal RV32IM guest that exercises HINT_STOREW, REVEAL and TERMINATE
//! using the same OpenVM custom-opcode encoding our interpreter recognises.
//!
//! Behaviour: read four u32 words from the hint stream, write them through
//! REVEAL at byte offsets 0, 4, 8, 12, then TERMINATE.

#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::panic::PanicInfo;

// Set sp before main runs.
global_asm!(
    r#"
    .section .text._start
    .globl _start
_start:
    la sp, _stack_top
    call main
    # Fallback terminate if main returns.
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
    // opcode=0x0b funct3=0b011 (PHANTOM) imm=0 (HintInput) rd=x0 rs1=x0
    unsafe {
        asm!(".insn i 0x0b, 3, x0, x0, 0", options(nostack));
    }
}

#[inline(always)]
fn hint_storew(dst: *mut u32) {
    // opcode=0x0b funct3=0b001 imm=0 rd=$dst rs1=x0
    unsafe {
        asm!(".insn i 0x0b, 1, {0}, x0, 0", in(reg) dst, options(nostack));
    }
}

#[inline(always)]
fn reveal(byte_offset: u32, value: u32) {
    // opcode=0x0b funct3=0b010 imm=0 rd=byte_offset rs1=value
    unsafe {
        asm!(".insn i 0x0b, 2, {0}, {1}, 0", in(reg) byte_offset, in(reg) value, options(nostack));
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
    // Pull the input stream into the hint stream. The first 4 bytes will be
    // the input length (prepended by the HintInput phantom), which we read
    // and discard, then echo the next 4 u32s back via REVEAL.
    hint_input();
    let mut len_word: u32 = 0;
    hint_storew(&mut len_word as *mut u32);
    let _ = len_word;
    let mut buf: [u32; 4] = [0; 4];
    for i in 0..4 {
        hint_storew(buf.as_mut_ptr().wrapping_add(i));
    }
    for i in 0..4 {
        reveal((i as u32) * 4, buf[i]);
    }
    terminate();
}
