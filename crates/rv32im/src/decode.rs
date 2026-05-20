//! RV32IM instruction decoder — sign-extended immediates, register fields,
//! convenience accessors. Custom opcodes (0x0b, 0x2b) are *not* dispatched
//! here; they flow through to `CustomOpHandler` from the executor.

#[inline]
pub fn opcode(insn: u32) -> u32 {
    insn & 0x7f
}
#[inline]
pub fn rd(insn: u32) -> u32 {
    (insn >> 7) & 0x1f
}
#[inline]
pub fn funct3(insn: u32) -> u32 {
    (insn >> 12) & 0x7
}
#[inline]
pub fn rs1(insn: u32) -> u32 {
    (insn >> 15) & 0x1f
}
#[inline]
pub fn rs2(insn: u32) -> u32 {
    (insn >> 20) & 0x1f
}
#[inline]
pub fn funct7(insn: u32) -> u32 {
    (insn >> 25) & 0x7f
}

/// I-type imm[11:0] sign-extended to u32.
#[inline]
pub fn imm_i(insn: u32) -> u32 {
    ((insn as i32) >> 20) as u32
}

/// S-type imm[11:0] sign-extended.
#[inline]
pub fn imm_s(insn: u32) -> u32 {
    let upper = ((insn as i32) >> 25) as u32; // sign-extends bits[31:25]
    let lower = (insn >> 7) & 0x1f;
    (upper << 5) | lower
}

/// B-type imm[12:1] sign-extended (bit 0 is always 0).
#[inline]
pub fn imm_b(insn: u32) -> u32 {
    let sign = ((insn as i32) >> 31) as u32; // -1 or 0
    let bit11 = (insn >> 7) & 1;
    let bits10_5 = (insn >> 25) & 0x3f;
    let bits4_1 = (insn >> 8) & 0xf;
    (sign << 12) | (bit11 << 11) | (bits10_5 << 5) | (bits4_1 << 1)
}

/// U-type imm[31:12] left in place (low 12 bits zero).
#[inline]
pub fn imm_u(insn: u32) -> u32 {
    insn & 0xffff_f000
}

/// J-type imm[20:1] sign-extended (bit 0 is always 0).
#[inline]
pub fn imm_j(insn: u32) -> u32 {
    let sign = ((insn as i32) >> 31) as u32;
    let bits19_12 = (insn >> 12) & 0xff;
    let bit11 = (insn >> 20) & 1;
    let bits10_1 = (insn >> 21) & 0x3ff;
    (sign << 20) | (bits19_12 << 12) | (bit11 << 11) | (bits10_1 << 1)
}

/// Shift amount for SLLI/SRLI/SRAI (low 5 bits of rs2 field).
#[inline]
pub fn shamt(insn: u32) -> u32 {
    rs2(insn) & 0x1f
}

// Opcode constants (the 32-bit instruction's bits[6:0]).
pub const OPCODE_LUI: u32 = 0b0110111;
pub const OPCODE_AUIPC: u32 = 0b0010111;
pub const OPCODE_JAL: u32 = 0b1101111;
pub const OPCODE_JALR: u32 = 0b1100111;
pub const OPCODE_BRANCH: u32 = 0b1100011;
pub const OPCODE_LOAD: u32 = 0b0000011;
pub const OPCODE_STORE: u32 = 0b0100011;
pub const OPCODE_OP_IMM: u32 = 0b0010011;
pub const OPCODE_OP: u32 = 0b0110011;
pub const OPCODE_MISC_MEM: u32 = 0b0001111; // FENCE
pub const OPCODE_SYSTEM: u32 = 0b1110011; // ECALL/EBREAK

// Custom opcode slots used by OpenVM.
pub const OPCODE_CUSTOM_0: u32 = 0b0001011; // 0x0b
pub const OPCODE_CUSTOM_1: u32 = 0b0101011; // 0x2b
