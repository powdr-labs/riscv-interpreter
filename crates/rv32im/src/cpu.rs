//! RV32IM CPU state and instruction execution loop.

use crate::decode::*;
use crate::memory::Memory;
use sim_elf::LoadedProgram;
use thiserror::Error;

/// Default top-of-stack — OpenVM's guest runtime expects a downward-growing
/// stack near the high end of the 32-bit address space.
pub const DEFAULT_STACK_TOP: u32 = 0xFFFF_FFF0;

#[derive(Debug, Clone, Copy)]
pub enum StepOutcome {
    /// Continue execution.
    Continue,
    /// Custom opcode requested termination (TERMINATE syscall). u32 is the exit code.
    Terminated(u32),
}

#[derive(Debug, Error)]
pub enum CpuError {
    #[error("illegal instruction 0x{insn:08x} at pc=0x{pc:08x}")]
    IllegalInstruction { pc: u32, insn: u32 },
    #[error("ebreak at pc=0x{0:08x}")]
    EBreak(u32),
    #[error("ecall at pc=0x{0:08x} (OpenVM uses custom opcode 0x0b for terminate; raw ecall not expected)")]
    ECall(u32),
    #[error("step limit exceeded at pc=0x{0:08x}")]
    StepLimitExceeded(u32),
    #[error("custom op handler error: {0}")]
    CustomOp(String),
}

/// Trait implemented by the precompiles crate. The executor delegates anything
/// using opcode 0x0b or 0x2b here.
pub trait CustomOpHandler {
    /// Handle a custom instruction. The handler reads/writes `cpu` state
    /// (registers, memory) as needed. Returning `Continue` advances PC by 4;
    /// returning `Terminated(code)` stops the loop.
    fn handle(&mut self, cpu: &mut Cpu, insn: u32) -> Result<StepOutcome, CpuError>;
}

#[derive(Debug)]
pub struct Cpu {
    pub pc: u32,
    pub x: [u32; 32], // x[0] is hard-wired to zero
    pub mem: Memory,
    pub steps: u64,
}

impl Cpu {
    /// Create a fresh CPU, load the program, set sp to `DEFAULT_STACK_TOP`.
    pub fn new(prog: &LoadedProgram) -> Self {
        let mut mem = Memory::new();
        for seg in &prog.segments {
            // Copy file bytes; remaining bytes up to mem_size remain zero
            // (BSS) because Memory pages are zero-initialised.
            mem.write_slice(seg.vaddr, &seg.data);
        }
        let mut x = [0u32; 32];
        x[2] = DEFAULT_STACK_TOP; // sp
        Cpu {
            pc: prog.entry,
            x,
            mem,
            steps: 0,
        }
    }

    #[inline]
    pub fn read_reg(&self, r: u32) -> u32 {
        if r == 0 {
            0
        } else {
            self.x[r as usize]
        }
    }

    #[inline]
    pub fn write_reg(&mut self, r: u32, val: u32) {
        if r != 0 {
            self.x[r as usize] = val;
        }
    }

    /// Run until terminate, error, or `max_steps` exceeded.
    pub fn run<H: CustomOpHandler>(
        &mut self,
        handler: &mut H,
        max_steps: u64,
    ) -> Result<u32, CpuError> {
        loop {
            if self.steps >= max_steps {
                return Err(CpuError::StepLimitExceeded(self.pc));
            }
            match self.step(handler)? {
                StepOutcome::Continue => {}
                StepOutcome::Terminated(code) => return Ok(code),
            }
            self.steps += 1;
        }
    }

    /// Execute exactly one instruction. PC is advanced by the instruction
    /// itself (branch/jump set PC to target; everything else +4).
    pub fn step<H: CustomOpHandler>(&mut self, handler: &mut H) -> Result<StepOutcome, CpuError> {
        let pc = self.pc;
        let insn = self.mem.read_u32(pc);

        match opcode(insn) {
            OPCODE_LUI => {
                self.write_reg(rd(insn), imm_u(insn));
                self.pc = pc.wrapping_add(4);
            }
            OPCODE_AUIPC => {
                self.write_reg(rd(insn), pc.wrapping_add(imm_u(insn)));
                self.pc = pc.wrapping_add(4);
            }
            OPCODE_JAL => {
                let target = pc.wrapping_add(imm_j(insn));
                self.write_reg(rd(insn), pc.wrapping_add(4));
                self.pc = target;
            }
            OPCODE_JALR => {
                let base = self.read_reg(rs1(insn));
                let target = base.wrapping_add(imm_i(insn)) & !1u32;
                let link = pc.wrapping_add(4);
                self.write_reg(rd(insn), link);
                self.pc = target;
            }
            OPCODE_BRANCH => self.exec_branch(insn)?,
            OPCODE_LOAD => self.exec_load(insn)?,
            OPCODE_STORE => self.exec_store(insn)?,
            OPCODE_OP_IMM => self.exec_op_imm(insn)?,
            OPCODE_OP => self.exec_op(insn)?,
            OPCODE_MISC_MEM => {
                // FENCE / FENCE.I — no-op in this in-order single-hart sim.
                self.pc = pc.wrapping_add(4);
            }
            OPCODE_SYSTEM => {
                // ECALL/EBREAK. OpenVM uses custom opcode 0x0b for its own
                // terminate; a raw ecall is unexpected here. Treat as error.
                let f3 = funct3(insn);
                let imm = imm_i(insn) & 0xfff;
                match (f3, imm) {
                    (0, 0) => return Err(CpuError::ECall(pc)),
                    (0, 1) => return Err(CpuError::EBreak(pc)),
                    _ => return Err(CpuError::IllegalInstruction { pc, insn }),
                }
            }
            OPCODE_CUSTOM_0 | OPCODE_CUSTOM_1 => {
                // Convention: the custom-op handler MUST set `cpu.pc` to the
                // address it wants executed next (typically `pc + 4`, except
                // for branch-style ops like BEQ256). The executor does not
                // auto-advance for custom opcodes.
                let outcome = handler.handle(self, insn)?;
                match outcome {
                    StepOutcome::Continue => {}
                    StepOutcome::Terminated(code) => return Ok(StepOutcome::Terminated(code)),
                }
            }
            _ => return Err(CpuError::IllegalInstruction { pc, insn }),
        }

        Ok(StepOutcome::Continue)
    }

    // ----- helpers for each opcode group -------------------------------------

    fn exec_branch(&mut self, insn: u32) -> Result<(), CpuError> {
        let a = self.read_reg(rs1(insn));
        let b = self.read_reg(rs2(insn));
        let taken = match funct3(insn) {
            0 => a == b,                       // BEQ
            1 => a != b,                       // BNE
            4 => (a as i32) < (b as i32),      // BLT
            5 => (a as i32) >= (b as i32),     // BGE
            6 => a < b,                        // BLTU
            7 => a >= b,                       // BGEU
            _ => {
                return Err(CpuError::IllegalInstruction {
                    pc: self.pc,
                    insn,
                })
            }
        };
        self.pc = if taken {
            self.pc.wrapping_add(imm_b(insn))
        } else {
            self.pc.wrapping_add(4)
        };
        Ok(())
    }

    fn exec_load(&mut self, insn: u32) -> Result<(), CpuError> {
        let addr = self.read_reg(rs1(insn)).wrapping_add(imm_i(insn));
        let val = match funct3(insn) {
            0 => (self.mem.read_u8(addr) as i8) as i32 as u32,  // LB
            1 => (self.mem.read_u16(addr) as i16) as i32 as u32, // LH
            2 => self.mem.read_u32(addr),                        // LW
            4 => self.mem.read_u8(addr) as u32,                  // LBU
            5 => self.mem.read_u16(addr) as u32,                 // LHU
            _ => {
                return Err(CpuError::IllegalInstruction {
                    pc: self.pc,
                    insn,
                })
            }
        };
        self.write_reg(rd(insn), val);
        self.pc = self.pc.wrapping_add(4);
        Ok(())
    }

    fn exec_store(&mut self, insn: u32) -> Result<(), CpuError> {
        let addr = self.read_reg(rs1(insn)).wrapping_add(imm_s(insn));
        let val = self.read_reg(rs2(insn));
        match funct3(insn) {
            0 => self.mem.write_u8(addr, val as u8),             // SB
            1 => self.mem.write_u16(addr, val as u16),           // SH
            2 => self.mem.write_u32(addr, val),                  // SW
            _ => {
                return Err(CpuError::IllegalInstruction {
                    pc: self.pc,
                    insn,
                })
            }
        }
        self.pc = self.pc.wrapping_add(4);
        Ok(())
    }

    fn exec_op_imm(&mut self, insn: u32) -> Result<(), CpuError> {
        let a = self.read_reg(rs1(insn));
        let imm = imm_i(insn);
        let f3 = funct3(insn);
        let val = match f3 {
            0 => a.wrapping_add(imm),                              // ADDI
            2 => ((a as i32) < (imm as i32)) as u32,               // SLTI
            3 => (a < imm) as u32,                                 // SLTIU
            4 => a ^ imm,                                          // XORI
            6 => a | imm,                                          // ORI
            7 => a & imm,                                          // ANDI
            1 => a << shamt(insn),                                 // SLLI
            5 => {
                // SRLI vs SRAI distinguished by funct7 bit 30 (0x20 << 25-25 = bit 30)
                let f7 = funct7(insn);
                if f7 == 0 {
                    a >> shamt(insn)
                } else if f7 == 0x20 {
                    ((a as i32) >> shamt(insn)) as u32
                } else {
                    return Err(CpuError::IllegalInstruction { pc: self.pc, insn });
                }
            }
            _ => unreachable!("funct3 is 3 bits"),
        };
        self.write_reg(rd(insn), val);
        self.pc = self.pc.wrapping_add(4);
        Ok(())
    }

    fn exec_op(&mut self, insn: u32) -> Result<(), CpuError> {
        let a = self.read_reg(rs1(insn));
        let b = self.read_reg(rs2(insn));
        let f3 = funct3(insn);
        let f7 = funct7(insn);
        let val = match (f7, f3) {
            // Base integer
            (0x00, 0) => a.wrapping_add(b),                         // ADD
            (0x20, 0) => a.wrapping_sub(b),                         // SUB
            (0x00, 1) => a.wrapping_shl(b & 0x1f),                  // SLL
            (0x00, 2) => ((a as i32) < (b as i32)) as u32,          // SLT
            (0x00, 3) => (a < b) as u32,                            // SLTU
            (0x00, 4) => a ^ b,                                     // XOR
            (0x00, 5) => a.wrapping_shr(b & 0x1f),                  // SRL
            (0x20, 5) => ((a as i32).wrapping_shr(b & 0x1f)) as u32, // SRA
            (0x00, 6) => a | b,                                     // OR
            (0x00, 7) => a & b,                                     // AND
            // M extension (funct7 == 1)
            (0x01, 0) => a.wrapping_mul(b),                         // MUL
            (0x01, 1) => {
                let s = (a as i32 as i64) * (b as i32 as i64);
                (s >> 32) as u32
            } // MULH
            (0x01, 2) => {
                let s = (a as i32 as i64) * (b as u32 as i64);
                (s >> 32) as u32
            } // MULHSU
            (0x01, 3) => {
                let s = (a as u64) * (b as u64);
                (s >> 32) as u32
            } // MULHU
            (0x01, 4) => {
                // DIV (signed)
                if b == 0 {
                    u32::MAX
                } else if a == 0x8000_0000 && b == u32::MAX {
                    0x8000_0000
                } else {
                    ((a as i32).wrapping_div(b as i32)) as u32
                }
            }
            (0x01, 5) => {
                // DIVU
                if b == 0 {
                    u32::MAX
                } else {
                    a / b
                }
            }
            (0x01, 6) => {
                // REM (signed)
                if b == 0 {
                    a
                } else if a == 0x8000_0000 && b == u32::MAX {
                    0
                } else {
                    ((a as i32).wrapping_rem(b as i32)) as u32
                }
            }
            (0x01, 7) => {
                // REMU
                if b == 0 {
                    a
                } else {
                    a % b
                }
            }
            _ => {
                return Err(CpuError::IllegalInstruction {
                    pc: self.pc,
                    insn,
                })
            }
        };
        self.write_reg(rd(insn), val);
        self.pc = self.pc.wrapping_add(4);
        Ok(())
    }
}
