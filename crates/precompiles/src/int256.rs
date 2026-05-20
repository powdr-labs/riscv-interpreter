//! 256-bit integer precompiles (opcode 0x0b, funct3=0b101) and BEQ256
//! (opcode 0x0b, funct3=0b110).
//!
//! All operands are 32-byte little-endian buffers in guest memory. Operations
//! match the Int256Funct7 enum from openvm-bigint-guest:
//!   0=Add 1=Sub 2=Xor 3=Or 4=And 5=Sll 6=Srl 7=Sra 8=Slt 9=Sltu 10=Mul
//!
//! BEQ256 is B-type: branches if [rs1] == [rs2] (both 32 bytes); imm_b is the
//! branch offset.

use crate::encoding::{
    INT256_ADD, INT256_AND, INT256_MUL, INT256_OR, INT256_SLL, INT256_SLT, INT256_SLTU, INT256_SRA,
    INT256_SRL, INT256_SUB, INT256_XOR,
};
use sim_rv32im::{Cpu, CpuError};

fn rd(insn: u32) -> u32 {
    (insn >> 7) & 0x1f
}
fn rs1(insn: u32) -> u32 {
    (insn >> 15) & 0x1f
}
fn rs2(insn: u32) -> u32 {
    (insn >> 20) & 0x1f
}
fn funct7(insn: u32) -> u32 {
    (insn >> 25) & 0x7f
}

fn imm_b(insn: u32) -> u32 {
    let sign = ((insn as i32) >> 31) as u32;
    let bit11 = (insn >> 7) & 1;
    let bits10_5 = (insn >> 25) & 0x3f;
    let bits4_1 = (insn >> 8) & 0xf;
    (sign << 12) | (bit11 << 11) | (bits10_5 << 5) | (bits4_1 << 1)
}

fn read32(cpu: &Cpu, ptr: u32) -> [u8; 32] {
    let mut b = [0u8; 32];
    for i in 0..32 {
        b[i] = cpu.mem.read_u8(ptr.wrapping_add(i as u32));
    }
    b
}
fn write32(cpu: &mut Cpu, ptr: u32, val: &[u8; 32]) {
    for i in 0..32 {
        cpu.mem.write_u8(ptr.wrapping_add(i as u32), val[i]);
    }
}

fn add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut r = [0u8; 32];
    let mut carry: u16 = 0;
    for i in 0..32 {
        let s = a[i] as u16 + b[i] as u16 + carry;
        r[i] = s as u8;
        carry = s >> 8;
    }
    r
}
fn sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut r = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in 0..32 {
        let s = a[i] as i16 - b[i] as i16 - borrow;
        if s < 0 {
            r[i] = (s + 256) as u8;
            borrow = 1;
        } else {
            r[i] = s as u8;
            borrow = 0;
        }
    }
    r
}
fn xor(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut r = [0u8; 32];
    for i in 0..32 {
        r[i] = a[i] ^ b[i];
    }
    r
}
fn and(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut r = [0u8; 32];
    for i in 0..32 {
        r[i] = a[i] & b[i];
    }
    r
}
fn or(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut r = [0u8; 32];
    for i in 0..32 {
        r[i] = a[i] | b[i];
    }
    r
}

/// Shift amount: low 8 bits of `b` (matches OpenVM, since shifts by ≥256 are
/// defined to return 0 anyway).
fn shift_amount(b: &[u8; 32]) -> u32 {
    b[0] as u32
}

fn shl(a: &[u8; 32], amt: u32) -> [u8; 32] {
    if amt >= 256 {
        return [0; 32];
    }
    let byte_off = (amt / 8) as usize;
    let bit_off = amt % 8;
    let mut r = [0u8; 32];
    if bit_off == 0 {
        for i in byte_off..32 {
            r[i] = a[i - byte_off];
        }
    } else {
        for i in 32 - 1..0 {
            let hi = if i >= byte_off { a[i - byte_off] } else { 0 };
            let lo = if i > byte_off { a[i - byte_off - 1] } else { 0 };
            r[i] = (hi << bit_off) | (lo >> (8 - bit_off));
        }
        // The simple range-loop above doesn't go backwards in Rust without
        // reversed iteration; redo:
        for i in (0..32).rev() {
            let hi = if i >= byte_off { a[i - byte_off] } else { 0 };
            let lo = if i > byte_off { a[i - byte_off - 1] } else { 0 };
            r[i] = (hi << bit_off) | (lo >> (8 - bit_off));
        }
    }
    r
}

fn shr_logical(a: &[u8; 32], amt: u32) -> [u8; 32] {
    if amt >= 256 {
        return [0; 32];
    }
    let byte_off = (amt / 8) as usize;
    let bit_off = amt % 8;
    let mut r = [0u8; 32];
    if bit_off == 0 {
        for i in 0..(32 - byte_off) {
            r[i] = a[i + byte_off];
        }
    } else {
        for i in 0..32 {
            let lo = if i + byte_off < 32 { a[i + byte_off] } else { 0 };
            let hi = if i + byte_off + 1 < 32 { a[i + byte_off + 1] } else { 0 };
            r[i] = (lo >> bit_off) | (hi << (8 - bit_off));
        }
    }
    r
}

fn shr_arith(a: &[u8; 32], amt: u32) -> [u8; 32] {
    let sign = (a[31] & 0x80) != 0;
    let fill: u8 = if sign { 0xff } else { 0x00 };
    if amt >= 256 {
        return [fill; 32];
    }
    let byte_off = (amt / 8) as usize;
    let bit_off = amt % 8;
    let mut r = [fill; 32];
    if bit_off == 0 {
        for i in 0..(32 - byte_off) {
            r[i] = a[i + byte_off];
        }
    } else {
        for i in 0..32 {
            let lo = if i + byte_off < 32 { a[i + byte_off] } else { fill };
            let hi = if i + byte_off + 1 < 32 { a[i + byte_off + 1] } else { fill };
            r[i] = (lo >> bit_off) | (hi << (8 - bit_off));
        }
    }
    r
}

fn mul(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    // Truncated 256x256 → 256 multiply, schoolbook over bytes.
    let mut r = [0u32; 32];
    for i in 0..32 {
        for j in 0..(32 - i) {
            r[i + j] += a[i] as u32 * b[j] as u32;
        }
    }
    let mut out = [0u8; 32];
    let mut carry: u32 = 0;
    for i in 0..32 {
        let v = r[i] + carry;
        out[i] = v as u8;
        carry = v >> 8;
    }
    out
}

fn cmp_unsigned(a: &[u8; 32], b: &[u8; 32]) -> std::cmp::Ordering {
    for i in (0..32).rev() {
        match a[i].cmp(&b[i]) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}
fn cmp_signed(a: &[u8; 32], b: &[u8; 32]) -> std::cmp::Ordering {
    let a_neg = (a[31] & 0x80) != 0;
    let b_neg = (b[31] & 0x80) != 0;
    match (a_neg, b_neg) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => cmp_unsigned(a, b),
    }
}

fn bool_to_u256(b: bool) -> [u8; 32] {
    let mut r = [0u8; 32];
    r[0] = b as u8;
    r
}

pub fn handle_int256(cpu: &mut Cpu, insn: u32) -> Result<(), CpuError> {
    let out = cpu.read_reg(rd(insn));
    let a_ptr = cpu.read_reg(rs1(insn));
    let b_ptr = cpu.read_reg(rs2(insn));
    let a = read32(cpu, a_ptr);
    let b = read32(cpu, b_ptr);
    let op = funct7(insn);
    let result = match op {
        x if x == INT256_ADD => add(&a, &b),
        x if x == INT256_SUB => sub(&a, &b),
        x if x == INT256_XOR => xor(&a, &b),
        x if x == INT256_OR => or(&a, &b),
        x if x == INT256_AND => and(&a, &b),
        x if x == INT256_SLL => shl(&a, shift_amount(&b)),
        x if x == INT256_SRL => shr_logical(&a, shift_amount(&b)),
        x if x == INT256_SRA => shr_arith(&a, shift_amount(&b)),
        x if x == INT256_SLT => bool_to_u256(cmp_signed(&a, &b) == std::cmp::Ordering::Less),
        x if x == INT256_SLTU => bool_to_u256(cmp_unsigned(&a, &b) == std::cmp::Ordering::Less),
        x if x == INT256_MUL => mul(&a, &b),
        _ => {
            return Err(CpuError::CustomOp(format!(
                "unknown INT256 funct7={} at pc=0x{:08x}",
                op, cpu.pc
            )))
        }
    };
    write32(cpu, out, &result);
    Ok(())
}

/// BEQ256: branch-if-equal on two 32-byte values addressed by `[rs1]` and
/// `[rs2]`. PC is set to `pc + imm_b` if equal, otherwise `pc + 4`.
pub fn handle_beq256(cpu: &mut Cpu, insn: u32) -> Result<(), CpuError> {
    let a_ptr = cpu.read_reg(rs1(insn));
    let b_ptr = cpu.read_reg(rs2(insn));
    let a = read32(cpu, a_ptr);
    let b = read32(cpu, b_ptr);
    let target = if a == b {
        cpu.pc.wrapping_add(imm_b(insn))
    } else {
        cpu.pc.wrapping_add(4)
    };
    cpu.pc = target;
    Ok(())
}
