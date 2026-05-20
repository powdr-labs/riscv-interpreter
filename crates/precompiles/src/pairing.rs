//! Pairing precompiles (opcode 0x2b, funct3=0b011).
//!
//! The powdr-labs/openvm fork's pairing extension exposes a single op:
//!   `PairingBaseFunct7::HintFinalExp = 0` (per pairing-supported curve).
//!
//! For BN254 (curve idx 0) the contract is:
//! - `rs1` → pointer to `{p_ptr: u32, p_len: u32}` (G1 affine array)
//! - `rs2` → pointer to `{q_ptr: u32, q_len: u32}` (G2 affine array)
//! - G1 affine point  = 64 bytes  (x_le ‖ y_le, each Fq = 32 bytes)
//! - G2 affine point  = 128 bytes (x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1, each Fq = 32B)
//!
//! Host computes:
//!   f = multi_miller_loop(P[], Q[])
//!   (c, u) = final_exp_hint(f)              [Gnark residue-witness algo]
//! Pushes c (12 × 32 = 384 B) then u (384 B) to `hint_stream`.
//!
//! Algorithm transcribed from
//! `extensions/pairing/guest/src/halo2curves_shims/bn254/final_exp.rs` in
//! the powdr-labs openvm fork at v2-powdr-beta.2. Original source:
//! https://eprint.iacr.org/2024/640.pdf (Theorem 3, Alg. 4) and Gnark
//! https://github.com/Consensys/gnark/blob/.../std/algebra/emulated/sw_bn254/hints.go

use crate::encoding::PAIRING_MAX_KINDS;
use crate::PrecompileHandler;
use sim_rv32im::{Cpu, CpuError};

#[cfg(feature = "pairing")]
use crate::{bls12_381_hint, bn254_hint};

pub fn handle_pairing(h: &mut PrecompileHandler, cpu: &mut Cpu, insn: u32) -> Result<(), CpuError> {
    let f7 = (insn >> 25) & 0x7f;
    let idx = (f7 / PAIRING_MAX_KINDS) as usize;
    let op = f7 % PAIRING_MAX_KINDS;
    let name = h.pairings.get(idx).copied().unwrap_or("<out-of-range>");

    if op != 0 {
        return Err(CpuError::CustomOp(format!(
            "pairing op={} (only HintFinalExp=0 is defined) for {} at pc=0x{:08x}",
            op, name, cpu.pc
        )));
    }

    #[cfg(feature = "pairing")]
    match name {
        "bn254" => bn254_hint::hint_final_exp(h, cpu, insn),
        "bls12_381" => bls12_381_hint::hint_final_exp(h, cpu, insn),
        _ => Err(CpuError::CustomOp(format!(
            "unknown pairing curve {} at pc=0x{:08x}",
            name, cpu.pc
        ))),
    }

    #[cfg(not(feature = "pairing"))]
    Err(CpuError::CustomOp(format!(
        "pairing op at pc=0x{:08x} but feature 'pairing' is disabled",
        cpu.pc
    )))
}
