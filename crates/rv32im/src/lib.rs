//! Pure-Rust RV32IM interpreter.
//!
//! This crate intentionally knows nothing about OpenVM precompiles. Custom
//! opcodes (0x0b custom-0, 0x2b custom-1) are forwarded through the
//! `CustomOpHandler` trait so a separate crate can implement the syscalls
//! and crypto operations on top.

pub mod cpu;
pub mod decode;
pub mod memory;

pub use cpu::{Cpu, CpuError, CustomOpHandler, StepOutcome, DEFAULT_STACK_TOP};
pub use memory::Memory;

#[cfg(test)]
mod tests {
    use super::*;
    use sim_elf::{LoadedProgram, Segment};

    struct NopHandler;
    impl CustomOpHandler for NopHandler {
        fn handle(&mut self, _cpu: &mut Cpu, _insn: u32) -> Result<StepOutcome, CpuError> {
            Ok(StepOutcome::Terminated(0))
        }
    }

    fn prog(insns: &[u32]) -> LoadedProgram {
        let mut data = Vec::with_capacity(insns.len() * 4);
        for &i in insns {
            data.extend_from_slice(&i.to_le_bytes());
        }
        LoadedProgram {
            entry: 0x1000,
            segments: vec![Segment {
                vaddr: 0x1000,
                mem_size: data.len() as u32,
                writable: false,
                executable: true,
                data,
            }],
        }
    }

    #[test]
    fn addi_chain() {
        // addi x1, x0, 5
        // addi x2, x1, 7
        // addi x3, x2, -3
        // 0x0b/funct3=0 terminate (custom-0)
        let addi = |rd: u32, rs1: u32, imm: i32| -> u32 {
            let imm = (imm as u32) & 0xfff;
            (imm << 20) | (rs1 << 15) | (0u32 << 12) | (rd << 7) | 0b0010011
        };
        let term = 0b0001011; // opcode 0x0b, funct3 = 0
        let p = prog(&[addi(1, 0, 5), addi(2, 1, 7), addi(3, 2, -3), term]);
        let mut cpu = Cpu::new(&p);
        let mut h = NopHandler;
        cpu.run(&mut h, 100).unwrap();
        assert_eq!(cpu.read_reg(1), 5);
        assert_eq!(cpu.read_reg(2), 12);
        assert_eq!(cpu.read_reg(3), 9);
    }

    #[test]
    fn mul_div() {
        // x1 = 12; x2 = -3 (signed); x3 = x1 * x2; x4 = x1 / x2 (signed)
        let addi = |rd: u32, rs1: u32, imm: i32| -> u32 {
            let imm = (imm as u32) & 0xfff;
            (imm << 20) | (rs1 << 15) | (rd << 7) | 0b0010011
        };
        let mul = |rd: u32, rs1: u32, rs2: u32| -> u32 {
            (1u32 << 25) | (rs2 << 20) | (rs1 << 15) | (0u32 << 12) | (rd << 7) | 0b0110011
        };
        let div = |rd: u32, rs1: u32, rs2: u32| -> u32 {
            (1u32 << 25) | (rs2 << 20) | (rs1 << 15) | (4u32 << 12) | (rd << 7) | 0b0110011
        };
        let term = 0b0001011;
        let p = prog(&[
            addi(1, 0, 12),
            addi(2, 0, -3),
            mul(3, 1, 2),
            div(4, 1, 2),
            term,
        ]);
        let mut cpu = Cpu::new(&p);
        let mut h = NopHandler;
        cpu.run(&mut h, 100).unwrap();
        assert_eq!(cpu.read_reg(3) as i32, -36);
        assert_eq!(cpu.read_reg(4) as i32, -4);
    }

    #[test]
    fn jal_link_then_terminate() {
        // jal x1, +8 ; halts at the second insn, which is just a terminate.
        let jal = (8u32 << 20 >> 9 /*not needed for offset 8*/) // assemble below
            | (0 /*placeholder*/);
        // Actually assemble JAL with rd=x1 and imm=8 (J-type encoding):
        //   imm[20|10:1|11|19:12] in [31|30:21|20|19:12]
        // For imm=8 the only set bit is bit3 of the raw offset, so:
        //   imm[10:1] = 0b00_0000_0100 (4), bit 11 = 0, bits[19:12]=0, sign=0
        // Encoded immediate field placement:
        //   insn[31] = sign (0)
        //   insn[30:21] = imm[10:1] = 0b00_0000_0100 (=4)
        //   insn[20] = imm[11] = 0
        //   insn[19:12] = imm[19:12] = 0
        let _ = jal;
        let jal_x1_plus8: u32 = (0 << 31)
            | (0 << 12) // imm[19:12]
            | (0 << 20) // imm[11]
            | ((4u32) << 21) // imm[10:1] = 4
            | (1 << 7)  // rd=x1
            | 0b1101111;
        let term = 0b0001011;
        // The JAL is at 0x1000, target = 0x1008
        let p = prog(&[jal_x1_plus8, 0xdeadbeef /* skipped */, term]);
        let mut cpu = Cpu::new(&p);
        let mut h = NopHandler;
        cpu.run(&mut h, 100).unwrap();
        assert_eq!(cpu.read_reg(1), 0x1004);
    }
}
