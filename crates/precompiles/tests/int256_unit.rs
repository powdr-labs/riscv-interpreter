//! Unit tests for INT256 ops driven directly through the dispatcher (no guest
//! ELF). We construct a tiny program in memory whose only purpose is to host
//! the custom instructions; we set up registers, point them at scratch
//! memory holding little-endian 256-bit values, fire the instruction, and
//! read the result back.

use sim_elf::{LoadedProgram, Segment};
use sim_precompiles::PrecompileHandler;
use sim_rv32im::{Cpu, CustomOpHandler};

/// Build a tiny program of one instruction `insn` at vaddr 0x100.
fn make_cpu(insn: u32) -> Cpu {
    let mut data = Vec::new();
    data.extend_from_slice(&insn.to_le_bytes());
    let prog = LoadedProgram {
        entry: 0x100,
        segments: vec![Segment {
            vaddr: 0x100,
            mem_size: 4,
            writable: false,
            executable: true,
            data,
        }],
    };
    Cpu::new(&prog)
}

fn put_u256(cpu: &mut Cpu, addr: u32, lo: u128, hi: u128) {
    for i in 0..16 {
        cpu.mem.write_u8(addr + i as u32, ((lo >> (8 * i)) & 0xff) as u8);
    }
    for i in 0..16 {
        cpu.mem.write_u8(addr + 16 + i as u32, ((hi >> (8 * i)) & 0xff) as u8);
    }
}
fn get_u256(cpu: &Cpu, addr: u32) -> (u128, u128) {
    let mut lo: u128 = 0;
    let mut hi: u128 = 0;
    for i in 0..16 {
        lo |= (cpu.mem.read_u8(addr + i) as u128) << (8 * i);
        hi |= (cpu.mem.read_u8(addr + 16 + i) as u128) << (8 * i);
    }
    (lo, hi)
}

/// Encode a custom-0 R-type insn: opcode=0x0b, funct3=0b101 (INT256),
/// funct7=op, rd=10, rs1=11, rs2=12.
fn enc_int256(op: u32) -> u32 {
    (op << 25) | (12 << 20) | (11 << 15) | (0b101 << 12) | (10 << 7) | 0x0b
}

fn run_op(op: u32, a: (u128, u128), b: (u128, u128)) -> (u128, u128) {
    let insn = enc_int256(op);
    let mut cpu = make_cpu(insn);
    cpu.write_reg(10, 0x1000); // out
    cpu.write_reg(11, 0x2000); // a
    cpu.write_reg(12, 0x3000); // b
    put_u256(&mut cpu, 0x2000, a.0, a.1);
    put_u256(&mut cpu, 0x3000, b.0, b.1);
    let mut h = PrecompileHandler::new(Vec::new());
    h.handle(&mut cpu, insn).unwrap();
    get_u256(&cpu, 0x1000)
}

#[test]
fn int256_add() {
    let r = run_op(0 /*Add*/, (5, 0), (7, 0));
    assert_eq!(r, (12, 0));
}

#[test]
fn int256_add_carry() {
    let r = run_op(0, (u128::MAX, 0), (1, 0));
    assert_eq!(r, (0, 1));
}

#[test]
fn int256_sub_borrow() {
    let r = run_op(1, (0, 1), (1, 0));
    assert_eq!(r, (u128::MAX, 0));
}

#[test]
fn int256_mul() {
    let r = run_op(10, (1234, 0), (5678, 0));
    assert_eq!(r, (1234 * 5678, 0));
}

#[test]
fn int256_xor() {
    let r = run_op(2, (0xff00, 0xaaaa), (0x0ff0, 0x5555));
    assert_eq!(r, (0xff00 ^ 0x0ff0, 0xaaaa ^ 0x5555));
}

#[test]
fn int256_sll_8() {
    let amt = (8u128, 0u128);
    let r = run_op(5, (0x01_02_03_04, 0), amt);
    assert_eq!(r, (0x01_02_03_04 << 8, 0));
}

#[test]
fn int256_sltu() {
    let r = run_op(9, (5, 0), (7, 0));
    assert_eq!(r, (1, 0));
    let r = run_op(9, (7, 0), (5, 0));
    assert_eq!(r, (0, 0));
}
