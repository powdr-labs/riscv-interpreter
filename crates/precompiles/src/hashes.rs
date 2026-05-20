//! Hash primitives for the powdr-labs/openvm v2-powdr-beta.2 fork.
//!
//! Unlike the upstream openvm crate (which exposes a "full keccak256(bytes,
//! len)" precompile), the powdr fork drops to lower-level primitives that
//! the guest wrappers (`native_keccak256`, `zkvm_sha256_impl`) build full
//! hashes on top of:
//!
//! - **KECCAKF**  (funct7=0): one Keccak-f[1600] permutation on a 200-byte
//!   state buffer at `[rd]`. `rs1` and `rs2` are unused (`x0`).
//! - **XORIN**    (funct7=1): XOR `len` (rs2) bytes from `[rs1]` into the
//!   buffer at `[rd]`. Used to absorb input into the keccak state.
//! - **SHA256C**  (funct7=2): SHA-256 compression — writes a new 32-byte
//!   state to `[rd]` given prev_state at `[rs1]` and a 64-byte block at
//!   `[rs2]`.
//! - **SHA512C**  (funct7=3): SHA-512 compression — same shape, 64-byte
//!   state, 128-byte block.

use crate::{rd, rs1, rs2};
#[allow(deprecated)]
use sha2::compress256;
#[allow(deprecated)]
use sha2::digest::generic_array::GenericArray;
use sim_rv32im::{Cpu, CpuError};

pub fn do_keccakf(cpu: &mut Cpu, insn: u32) -> Result<(), CpuError> {
    let ptr = cpu.read_reg(rd(insn));
    // Read 25 u64 lanes (200 bytes) of state.
    let mut state = [0u64; 25];
    for i in 0..25 {
        let mut bs = [0u8; 8];
        for j in 0..8 {
            bs[j] = cpu.mem.read_u8(ptr.wrapping_add((i * 8 + j) as u32));
        }
        state[i] = u64::from_le_bytes(bs);
    }
    keccakf1600(&mut state);
    for i in 0..25 {
        let bs = state[i].to_le_bytes();
        for j in 0..8 {
            cpu.mem.write_u8(ptr.wrapping_add((i * 8 + j) as u32), bs[j]);
        }
    }
    Ok(())
}

pub fn do_xorin(cpu: &mut Cpu, insn: u32) -> Result<(), CpuError> {
    let dst = cpu.read_reg(rd(insn));
    let src = cpu.read_reg(rs1(insn));
    let len = cpu.read_reg(rs2(insn));
    for i in 0..len {
        let s = cpu.mem.read_u8(src.wrapping_add(i));
        let d = cpu.mem.read_u8(dst.wrapping_add(i));
        cpu.mem.write_u8(dst.wrapping_add(i), d ^ s);
    }
    Ok(())
}

pub fn do_sha256_compress(cpu: &mut Cpu, insn: u32) -> Result<(), CpuError> {
    let out_ptr = cpu.read_reg(rd(insn));
    let prev_ptr = cpu.read_reg(rs1(insn));
    let block_ptr = cpu.read_reg(rs2(insn));

    // openvm-circuit reads the state as `[u32; 8]` via a raw pointer cast
    // (`state.as_mut_ptr() as *mut [u32; 8]`). On RISC-V (LE), that means
    // each four-byte word is interpreted little-endian — we mirror that.
    let mut state = [0u32; 8];
    for i in 0..8 {
        let mut bs = [0u8; 4];
        for j in 0..4 {
            bs[j] = cpu.mem.read_u8(prev_ptr.wrapping_add((i * 4 + j) as u32));
        }
        state[i] = u32::from_le_bytes(bs);
    }

    let mut block = [0u8; 64];
    for i in 0..64 {
        block[i] = cpu.mem.read_u8(block_ptr.wrapping_add(i as u32));
    }
    let ga: GenericArray<u8, sha2::digest::consts::U64> = GenericArray::clone_from_slice(&block);
    compress256(&mut state, core::slice::from_ref(&ga));

    for i in 0..8 {
        let bs = state[i].to_le_bytes();
        for j in 0..4 {
            cpu.mem.write_u8(out_ptr.wrapping_add((i * 4 + j) as u32), bs[j]);
        }
    }
    Ok(())
}

/// In-place Keccak-f[1600] permutation. Standard 24-round Keccak.
fn keccakf1600(s: &mut [u64; 25]) {
    const RC: [u64; 24] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ];
    const ROTC: [u32; 24] = [
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
    ];
    const PIL: [usize; 24] = [
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
    ];
    for round in 0..24 {
        // theta
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for x in 0..5 {
            for y in 0..5 {
                s[x + 5 * y] ^= d[x];
            }
        }
        // rho + pi
        let mut t = s[1];
        for i in 0..24 {
            let j = PIL[i];
            let tmp = s[j];
            s[j] = t.rotate_left(ROTC[i]);
            t = tmp;
        }
        // chi
        for y in 0..5 {
            let mut row = [0u64; 5];
            for x in 0..5 {
                row[x] = s[x + 5 * y];
            }
            for x in 0..5 {
                s[x + 5 * y] = row[x] ^ (!row[(x + 1) % 5] & row[(x + 2) % 5]);
            }
        }
        // iota
        s[0] ^= RC[round];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccakf_zero_state() {
        // Known answer: keccak-f[1600] of the all-zero state. Vector from
        // RFC 8702 / tiny-keccak tests.
        let mut s = [0u64; 25];
        keccakf1600(&mut s);
        // First lane after one permutation of zero state:
        // 0xf1258f7940e1dde7. (Common reference value used by FIPS-202 vectors.)
        assert_eq!(s[0], 0xf1258f7940e1dde7);
    }
}
