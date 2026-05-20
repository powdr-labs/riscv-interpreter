//! OpenVM custom-opcode dispatcher.
//!
//! Implements `sim_rv32im::CustomOpHandler` so the bare RV32IM interpreter
//! can run OpenVM-modified ELFs while we handle the syscalls and crypto
//! precompiles in pure Rust.

use sim_rv32im::{Cpu, CpuError, CustomOpHandler, StepOutcome};

mod encoding;
use encoding::*;

#[cfg(feature = "modular")]
pub mod config;
#[cfg(feature = "modular")]
mod modular;

#[cfg(feature = "hashes")]
mod hashes;

#[cfg(feature = "ecc")]
mod ecc;

#[cfg(feature = "pairing")]
mod pairing;
#[cfg(feature = "pairing")]
mod bn254_hint;
#[cfg(feature = "pairing")]
mod bls12_381_hint;

mod int256;

#[cfg(feature = "modular")]
use config::{default_complex, default_curves, default_moduli, default_pairings};

/// I/O state mirroring openvm-circuit's `Streams<F>`.
///
/// `input_streams` is the queue the host populates (one entry per SDK
/// `StdIn::write_bytes` call). The HintInput phantom pops one entry, prepends
/// its length-as-u32, pads to a multiple of 4 bytes, and dumps the result
/// into `hint_stream`. `HINT_STOREW` / `HINT_BUFFER` pop bytes from
/// `hint_stream`.
#[derive(Debug, Default)]
pub struct IoState {
    /// FIFO of input "streams" — each entry is one `StdIn::write*` call.
    pub input_streams: std::collections::VecDeque<Vec<u8>>,
    /// Active byte buffer populated by HintInput; consumed by HINT_*.
    pub hint_stream: std::collections::VecDeque<u8>,
    /// Public output (sparse — extended as REVEAL writes at arbitrary offsets).
    pub output: Vec<u8>,
}

impl IoState {
    /// Convenience constructor for the common single-stream case.
    pub fn with_input(bytes: Vec<u8>) -> Self {
        let mut q = std::collections::VecDeque::new();
        q.push_back(bytes);
        Self {
            input_streams: q,
            hint_stream: std::collections::VecDeque::new(),
            output: Vec::new(),
        }
    }

    pub fn with_input_streams<I: IntoIterator<Item = Vec<u8>>>(streams: I) -> Self {
        Self {
            input_streams: streams.into_iter().collect(),
            hint_stream: std::collections::VecDeque::new(),
            output: Vec::new(),
        }
    }

    /// HintInput phantom: pop the next input stream, prepend its u32 LE
    /// length, pad to 4-byte boundary, push into `hint_stream` (overwriting
    /// any leftover bytes — that mirrors openvm's `streams.hint_stream.clear()`).
    fn hint_input(&mut self) -> Result<(), &'static str> {
        let entry = self.input_streams.pop_front().ok_or("EndOfInputStream")?;
        self.hint_stream.clear();
        for b in (entry.len() as u32).to_le_bytes() {
            self.hint_stream.push_back(b);
        }
        for b in &entry {
            self.hint_stream.push_back(*b);
        }
        // pad to next multiple of 4
        while self.hint_stream.len() % 4 != 0 {
            self.hint_stream.push_back(0);
        }
        Ok(())
    }

    fn read_hint_bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(self.hint_stream.pop_front().unwrap_or(0));
        }
        v
    }

    fn write_output(&mut self, offset: usize, bytes: &[u8]) {
        let end = offset + bytes.len();
        if self.output.len() < end {
            self.output.resize(end, 0);
        }
        self.output[offset..end].copy_from_slice(bytes);
    }
}

/// The default precompile handler the runner instantiates.
pub struct PrecompileHandler {
    pub io: IoState,
    #[cfg(feature = "modular")]
    pub moduli: Vec<config::ModulusEntry>,
    #[cfg(feature = "modular")]
    pub curves: Vec<config::CurveEntry>,
    #[cfg(feature = "modular")]
    pub complex: Vec<config::ModulusEntry>,
    #[cfg(feature = "modular")]
    pub pairings: Vec<&'static str>,
}

impl PrecompileHandler {
    pub fn new(input: Vec<u8>) -> Self {
        Self {
            io: IoState::with_input(input),
            #[cfg(feature = "modular")]
            moduli: default_moduli(),
            #[cfg(feature = "modular")]
            curves: default_curves(),
            #[cfg(feature = "modular")]
            complex: default_complex(),
            #[cfg(feature = "modular")]
            pairings: default_pairings(),
        }
    }
}

#[inline]
fn opcode(insn: u32) -> u32 {
    insn & 0x7f
}
#[inline]
fn funct3(insn: u32) -> u32 {
    (insn >> 12) & 0x7
}
#[inline]
fn funct7(insn: u32) -> u32 {
    (insn >> 25) & 0x7f
}
#[inline]
fn rd(insn: u32) -> u32 {
    (insn >> 7) & 0x1f
}
#[inline]
fn rs1(insn: u32) -> u32 {
    (insn >> 15) & 0x1f
}
#[inline]
fn rs2(insn: u32) -> u32 {
    (insn >> 20) & 0x1f
}
#[inline]
fn imm_i(insn: u32) -> u32 {
    ((insn as i32) >> 20) as u32
}

impl CustomOpHandler for PrecompileHandler {
    fn handle(&mut self, cpu: &mut Cpu, insn: u32) -> Result<StepOutcome, CpuError> {
        let op = opcode(insn);
        let f3 = funct3(insn);

        // PC of the instruction we just decoded — we'll advance to pc+4 by
        // default after dispatch (branch-style ops override this in their
        // handler body).
        let pc = cpu.pc;
        let outcome = match op {
            OPCODE_CUSTOM_0 => self.handle_custom0(cpu, insn, f3),
            OPCODE_CUSTOM_1 => self.handle_custom1(cpu, insn, f3),
            _ => return Err(CpuError::IllegalInstruction { pc: cpu.pc, insn }),
        }?;
        match outcome {
            StepOutcome::Continue => {
                // Only advance if the handler didn't already move PC away
                // from the current instruction.
                if cpu.pc == pc {
                    cpu.pc = pc.wrapping_add(4);
                }
            }
            StepOutcome::Terminated(_) => {}
        }
        Ok(outcome)
    }
}

impl PrecompileHandler {
    fn handle_custom0(
        &mut self,
        cpu: &mut Cpu,
        insn: u32,
        f3: u32,
    ) -> Result<StepOutcome, CpuError> {
        match f3 {
            F3_TERMINATE => {
                // I-type. rs1 holds an exit code in some openvm versions; we
                // don't strictly need it but pass it through.
                let code = cpu.read_reg(rs1(insn));
                tracing::debug!(pc = cpu.pc, code, "TERMINATE");
                Ok(StepOutcome::Terminated(code))
            }
            F3_HINT => {
                // I-type. imm distinguishes:
                //  imm = 0  → HINT_STOREW:  pop 4 bytes from hint_stream to [rd]
                //  imm = 1  → HINT_BUFFER:  pop 4*rs1 bytes from hint_stream to [rd]
                let imm = imm_i(insn) & 0xfff;
                let dst_ptr = cpu.read_reg(rd(insn));
                match imm {
                    x if x == HINT_STOREW_IMM => {
                        let bs = self.io.read_hint_bytes(4);
                        for (i, b) in bs.iter().enumerate() {
                            cpu.mem.write_u8(dst_ptr.wrapping_add(i as u32), *b);
                        }
                    }
                    x if x == HINT_BUFFER_IMM => {
                        let len_words = cpu.read_reg(rs1(insn));
                        let total = (len_words as usize) * 4;
                        let bs = self.io.read_hint_bytes(total);
                        for (i, b) in bs.iter().enumerate() {
                            cpu.mem.write_u8(dst_ptr.wrapping_add(i as u32), *b);
                        }
                    }
                    _ => {
                        return Err(CpuError::CustomOp(format!(
                            "unknown HINT imm 0x{:x} at pc=0x{:08x}",
                            imm, cpu.pc
                        )))
                    }
                }
                Ok(StepOutcome::Continue)
            }
            F3_REVEAL => {
                // I-type "store rs1 to [[rd] + imm]_3". rs1 = u32 value,
                // rd = byte-offset into public output, imm = additional offset.
                let value = cpu.read_reg(rs1(insn));
                let off = cpu.read_reg(rd(insn)).wrapping_add(imm_i(insn) & 0xfff) as usize;
                self.io.write_output(off, &value.to_le_bytes());
                tracing::debug!(off, value, "REVEAL");
                Ok(StepOutcome::Continue)
            }
            F3_PHANTOM => {
                let imm = imm_i(insn) & 0xfff;
                match imm {
                    x if x == PHANTOM_HINT_INPUT => {
                        self.io.hint_input().map_err(|e| {
                            CpuError::CustomOp(format!(
                                "HintInput at pc=0x{:08x}: {}",
                                cpu.pc, e
                            ))
                        })?;
                    }
                    x if x == PHANTOM_PRINT_STR => {
                        let ptr = cpu.read_reg(rd(insn));
                        let len = cpu.read_reg(rs1(insn));
                        let bytes = cpu.mem.read_vec(ptr, len as usize);
                        let s = String::from_utf8_lossy(&bytes);
                        tracing::info!(target: "guest_print", "{}", s);
                    }
                    _ => {
                        tracing::trace!(imm, "PHANTOM (noop)");
                    }
                }
                Ok(StepOutcome::Continue)
            }
            F3_HASH => {
                #[cfg(feature = "hashes")]
                {
                    let f7 = funct7(insn);
                    match f7 {
                        x if x == F7_KECCAKF => hashes::do_keccakf(cpu, insn)?,
                        x if x == F7_XORIN => hashes::do_xorin(cpu, insn)?,
                        x if x == F7_SHA256_COMPRESS => hashes::do_sha256_compress(cpu, insn)?,
                        _ => {
                            return Err(CpuError::CustomOp(format!(
                                "unknown hash funct7=0x{:x} at pc=0x{:08x}",
                                f7, cpu.pc
                            )))
                        }
                    }
                    return Ok(StepOutcome::Continue);
                }
                #[cfg(not(feature = "hashes"))]
                Err(CpuError::CustomOp(format!(
                    "hash op (funct7=0x{:x}) at pc=0x{:08x} but feature 'hashes' is disabled",
                    funct7(insn),
                    cpu.pc
                )))
            }
            F3_INT256 => {
                int256::handle_int256(cpu, insn)?;
                Ok(StepOutcome::Continue)
            }
            F3_BEQ256 => {
                // B-type. Compares 256-bit values at [rs1] and [rs2]; if equal,
                // PC += imm_b. Otherwise PC += 4.
                int256::handle_beq256(cpu, insn)?;
                // BEQ256 sets pc itself when taken; the executor will add 4
                // regardless on Continue, so we need to special-case here.
                // We'll model this by returning Continue but pre-adjust PC:
                // see int256.rs.
                Ok(StepOutcome::Continue)
            }
            F3_NATIVE_STOREW => {
                // Used only by openvm-internal continuation/native code, not
                // the guest we run. Treat as no-op for now.
                tracing::trace!("NATIVE_STOREW (ignored)");
                Ok(StepOutcome::Continue)
            }
            _ => Err(CpuError::CustomOp(format!(
                "custom-0 unknown funct3=0b{:03b} at pc=0x{:08x}",
                f3, cpu.pc
            ))),
        }
    }

    fn handle_custom1(
        &mut self,
        cpu: &mut Cpu,
        insn: u32,
        f3: u32,
    ) -> Result<StepOutcome, CpuError> {
        let _ = (insn, f3);
        match f3 {
            #[cfg(feature = "modular")]
            F3_MODULAR => {
                modular::handle_modular(self, cpu, insn)?;
                Ok(StepOutcome::Continue)
            }
            #[cfg(feature = "modular")]
            F3_COMPLEX => {
                modular::handle_complex(self, cpu, insn)?;
                Ok(StepOutcome::Continue)
            }
            #[cfg(feature = "ecc")]
            F3_SW => {
                ecc::handle_sw(self, cpu, insn)?;
                Ok(StepOutcome::Continue)
            }
            #[cfg(feature = "pairing")]
            F3_PAIRING => {
                pairing::handle_pairing(self, cpu, insn)?;
                Ok(StepOutcome::Continue)
            }
            _ => Err(CpuError::CustomOp(format!(
                "custom-1 funct3=0b{:03b} at pc=0x{:08x} — feature gated or unknown",
                f3, cpu.pc
            ))),
        }
    }
}
