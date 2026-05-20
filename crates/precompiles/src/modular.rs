//! Modular arithmetic (opcode 0x2b funct3=0b000) and complex-extension Fp2
//! (opcode 0x2b funct3=0b010) precompiles.
//!
//! Encoding: funct7 = mod_idx * 8 + base_op, where base_op is:
//!   0 = AddMod, 1 = SubMod, 2 = MulMod, 3 = DivMod, 4 = IsEqMod, 5 = Setup
//!
//! All operands are little-endian byte arrays of length `limb_bytes` (32 for
//! 256-bit moduli; 48 for BLS12-381's Fp). Result is the canonical
//! representative in `[0, p)`. IsEq writes a single 0/1 byte to `[rd]`.
//! Setup is a no-op for the interpreter.

use crate::config::ModulusEntry;
use crate::encoding::{
    MOD_ADD, MOD_DIV, MOD_ISEQ, MOD_MUL, MOD_SETUP, MOD_SUB, MODULAR_MAX_KINDS,
};

// Beyond the upstream openvm-org enum (Add..Setup), the powdr-labs fork at
// v2-powdr-beta.2 adds two HINT operations on the same `funct7 = mod_idx*8 + op`
// scheme. They don't write to memory; they push values into the hint_stream
// for the guest to consume via subsequent HINT_STOREW/HINT_BUFFER instructions.
const MOD_HINT_NON_QR: u32 = 6;
const MOD_HINT_SQRT: u32 = 7;
use crate::{rs1, rs2, PrecompileHandler};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::Zero;
use sim_rv32im::{Cpu, CpuError};

fn read_le(cpu: &Cpu, ptr: u32, n: usize) -> BigUint {
    let bytes = cpu.mem.read_vec(ptr, n);
    BigUint::from_bytes_le(&bytes)
}

fn write_le(cpu: &mut Cpu, ptr: u32, val: &BigUint, n: usize) {
    let mut bs = val.to_bytes_le();
    bs.resize(n, 0);
    for (i, b) in bs.iter().enumerate() {
        cpu.mem.write_u8(ptr.wrapping_add(i as u32), *b);
    }
}

/// Compute modular inverse via the extended Euclidean algorithm.
fn mod_inv(a: &BigUint, p: &BigUint) -> Option<BigUint> {
    use num_bigint::BigInt;
    use num_traits::One;
    if a.is_zero() {
        return None;
    }
    let (g, x, _) = extended_gcd(BigInt::from(a.clone()), BigInt::from(p.clone()));
    if g != BigInt::one() {
        None
    } else {
        let p_i = BigInt::from(p.clone());
        let inv = ((x % &p_i) + &p_i) % &p_i;
        Some(inv.to_biguint().unwrap())
    }
}

fn extended_gcd(
    a: num_bigint::BigInt,
    b: num_bigint::BigInt,
) -> (num_bigint::BigInt, num_bigint::BigInt, num_bigint::BigInt) {
    use num_bigint::BigInt;
    use num_traits::{One, Zero};
    if b.is_zero() {
        (a, BigInt::one(), BigInt::zero())
    } else {
        let (g, x1, y1) = extended_gcd(b.clone(), &a % &b);
        let x = y1.clone();
        let y = x1 - (&a / &b) * y1;
        (g, x, y)
    }
}

/// Direct port of `openvm-circuit/extensions/algebra/circuit/src/extension/modular.rs::find_non_qr`.
/// Uses fast paths for `p ≡ 3 (mod 4)` and `p ≡ 5 (mod 8)`, otherwise
/// rejection-samples uniformly with the same deterministic RNG (StdRng seeded
/// with all zeros) — matching the value openvm's HintNonQr produces.
fn find_non_qr_openvm(modulus: &BigUint) -> BigUint {
    use num_traits::One;
    use rand::{Rng, SeedableRng};
    if modulus % 4u32 == BigUint::from(3u8) {
        return modulus - BigUint::one();
    }
    if modulus % 8u32 == BigUint::from(5u8) {
        return BigUint::from(2u32);
    }
    let range = modulus - 3u32;
    let len = modulus.to_bytes_be().len();
    let mut buf = vec![0u8; len];
    let exponent = (modulus - BigUint::one()) >> 1;
    let pm1 = modulus - BigUint::one();
    let mut rng = rand::rngs::StdRng::from_seed([0u8; 32]);
    loop {
        rng.fill(buf.as_mut_slice());
        let val = BigUint::from_bytes_be(&buf);
        if val >= range {
            continue;
        }
        let non_qr = val + 2u32;
        if non_qr.modpow(&exponent, modulus) == pm1 {
            return non_qr;
        }
    }
}

/// Direct port of `mod_sqrt` from openvm-circuit's algebra extension. Returns
/// the same root openvm would (no normalisation to the smaller of the two
/// roots — important for downstream consumers that look at the raw value).
fn mod_sqrt_openvm(x: &BigUint, modulus: &BigUint, non_qr: &BigUint) -> Option<BigUint> {
    use num_traits::{One, Zero};
    if modulus % 4u32 == BigUint::from(3u8) {
        // x^(1/2) = x^((p+1)/4) when p = 3 mod 4
        let exponent = (modulus + BigUint::one()) >> 2;
        let ret = x.modpow(&exponent, modulus);
        if &ret * &ret % modulus == x % modulus {
            return Some(ret);
        }
        return None;
    }
    // Tonelli-Shanks
    let mut q = modulus - BigUint::one();
    let mut s = 0u32;
    while &q % 2u32 == BigUint::zero() {
        s += 1;
        q /= 2u32;
    }
    let z = non_qr;
    let mut m = s;
    let mut c = z.modpow(&q, modulus);
    let mut t = x.modpow(&q, modulus);
    let mut r = x.modpow(&((&q + BigUint::one()) >> 1), modulus);
    loop {
        if t == BigUint::zero() {
            return Some(BigUint::zero());
        }
        if t == BigUint::one() {
            return Some(r);
        }
        let mut i = 0u32;
        let mut tmp = t.clone();
        while tmp != BigUint::one() && i < m {
            tmp = &tmp * &tmp % modulus;
            i += 1;
        }
        if i == m {
            return None;
        }
        let mut b = c.clone();
        for _ in 0..m - i - 1 {
            b = &b * &b % modulus;
        }
        m = i;
        c = &b * &b % modulus;
        t = ((&t * &b % modulus) * &b) % modulus;
        r = (&r * &b) % modulus;
    }
}

/// Replace the host hint stream with `bytes` — matches openvm-circuit
/// `streams.hint_stream = ...` for HintNonQr / HintSqrt.
fn replace_hint_stream(h: &mut crate::PrecompileHandler, bytes: &[u8]) {
    h.io.hint_stream.clear();
    for b in bytes {
        h.io.hint_stream.push_back(*b);
    }
}

fn do_mod_op(
    cpu: &mut Cpu,
    insn: u32,
    entry: &ModulusEntry,
    op: u32,
) -> Result<(), CpuError> {
    let rd_idx = (insn >> 7) & 0x1f;
    let out = cpu.read_reg(rd_idx);
    let a_ptr = cpu.read_reg(rs1(insn));
    let b_ptr = cpu.read_reg(rs2(insn));
    let n = entry.limb_bytes;
    let a = read_le(cpu, a_ptr, n);
    let b = read_le(cpu, b_ptr, n);
    let p = &entry.modulus;

    match op {
        x if x == MOD_ADD => {
            let r = (a + b) % p;
            write_le(cpu, out, &r, n);
        }
        x if x == MOD_SUB => {
            let r = if a >= b { (a - b) % p } else { (p + a - b) % p };
            write_le(cpu, out, &r, n);
        }
        x if x == MOD_MUL => {
            let r = (a * b) % p;
            write_le(cpu, out, &r, n);
        }
        x if x == MOD_DIV => {
            let inv = mod_inv(&b, p).ok_or_else(|| {
                CpuError::CustomOp(format!(
                    "modular inverse of zero/non-coprime b in {} divmod at pc=0x{:08x}",
                    entry.name, cpu.pc
                ))
            })?;
            let r = (a * inv) % p;
            write_le(cpu, out, &r, n);
        }
        x if x == MOD_ISEQ => {
            // IsEqMod writes directly to register `rd` (RV32_REGISTER_AS in
            // openvm-circuit), NOT to memory at [rd]. Result is a single
            // byte 0/1 zero-extended to u32.
            let eq = (a % p) == (b % p);
            cpu.write_reg(rd_idx, eq as u32);
        }
        x if x == MOD_SETUP => {
            // No-op: moduli are static in our config.
            tracing::trace!(modulus = entry.name, "MOD_SETUP (noop)");
        }
        _ => {
            return Err(CpuError::CustomOp(format!(
                "unknown modular op={} for modulus {} at pc=0x{:08x}",
                op, entry.name, cpu.pc
            )))
        }
    }
    Ok(())
}

pub fn handle_modular(h: &mut PrecompileHandler, cpu: &mut Cpu, insn: u32) -> Result<(), CpuError> {
    let f7 = (insn >> 25) & 0x7f;
    let mod_idx = (f7 / MODULAR_MAX_KINDS) as usize;
    let op = f7 % MODULAR_MAX_KINDS;
    // Counter for diagnostics; cheap relaxed atomic increments.
    static CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let _ = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let entry = h
        .moduli
        .get(mod_idx)
        .ok_or_else(|| {
            CpuError::CustomOp(format!(
                "modular: mod_idx {} out of range (have {}) at pc=0x{:08x}",
                mod_idx,
                h.moduli.len(),
                cpu.pc
            ))
        })?
        .clone();
    if op == MOD_HINT_NON_QR {
        let non_qr = find_non_qr_openvm(&entry.modulus);
        let mut bs = non_qr.to_bytes_le();
        bs.resize(entry.limb_bytes, 0);
        replace_hint_stream(h, &bs);
        return Ok(());
    }
    if op == MOD_HINT_SQRT {
        let x_ptr = cpu.read_reg((insn >> 15) & 0x1f);
        let x = read_le(cpu, x_ptr, entry.limb_bytes);
        let non_qr = find_non_qr_openvm(&entry.modulus);
        let (success, sqrt) = match mod_sqrt_openvm(&x, &entry.modulus, &non_qr) {
            Some(s) => (true, s),
            None => {
                let prod = (&x * &non_qr) % &entry.modulus;
                let s = mod_sqrt_openvm(&prod, &entry.modulus, &non_qr)
                    .expect("either x or x*non_qr should be a square");
                (false, s)
            }
        };
        // Wire layout: 4 bytes flag (u32 LE, 0=non-QR, 1=QR) + `limb_bytes`
        // bytes of sqrt, zero-padded to `limb_bytes`. Matches openvm's
        // `chain(once(flag)).chain(repeat 0).take(4).chain(sqrt.le).take(N)`.
        let mut hint = Vec::with_capacity(4 + entry.limb_bytes);
        hint.push(success as u8);
        hint.extend_from_slice(&[0u8; 3]);
        let mut bs = sqrt.to_bytes_le();
        bs.resize(entry.limb_bytes, 0);
        hint.extend_from_slice(&bs);
        replace_hint_stream(h, &hint);
        return Ok(());
    }
    do_mod_op(cpu, insn, &entry, op)
}

/// Complex Fp2 arithmetic over c0 + c1 * X where X^2 = -1 (the openvm
/// convention for bn254 and bls12-381 Fp2). Each Fp2 element is encoded as
/// `c0 || c1` (each `limb_bytes` bytes, little-endian).
pub fn handle_complex(h: &mut PrecompileHandler, cpu: &mut Cpu, insn: u32) -> Result<(), CpuError> {
    let f7 = (insn >> 25) & 0x7f;
    // Reuse `MODULAR_MAX_KINDS` since complex uses the same 8-slot pattern.
    let idx = (f7 / MODULAR_MAX_KINDS) as usize;
    let op = f7 % MODULAR_MAX_KINDS;
    let entry = h
        .complex
        .get(idx)
        .ok_or_else(|| {
            CpuError::CustomOp(format!(
                "complex: idx {} out of range (have {}) at pc=0x{:08x}",
                idx,
                h.complex.len(),
                cpu.pc
            ))
        })?
        .clone();

    let n = entry.limb_bytes;
    let rd_idx = (insn >> 7) & 0x1f;
    let out = cpu.read_reg(rd_idx);
    let a_ptr = cpu.read_reg(rs1(insn));
    let b_ptr = cpu.read_reg(rs2(insn));
    let p = &entry.modulus;

    let a0 = read_le(cpu, a_ptr, n);
    let a1 = read_le(cpu, a_ptr.wrapping_add(n as u32), n);
    let b0 = read_le(cpu, b_ptr, n);
    let b1 = read_le(cpu, b_ptr.wrapping_add(n as u32), n);

    match op {
        x if x == MOD_ADD => {
            let r0 = (&a0 + &b0) % p;
            let r1 = (&a1 + &b1) % p;
            write_le(cpu, out, &r0, n);
            write_le(cpu, out.wrapping_add(n as u32), &r1, n);
        }
        x if x == MOD_SUB => {
            let r0 = if a0 >= b0 { (&a0 - &b0) % p } else { (p + &a0 - &b0) % p };
            let r1 = if a1 >= b1 { (&a1 - &b1) % p } else { (p + &a1 - &b1) % p };
            write_le(cpu, out, &r0, n);
            write_le(cpu, out.wrapping_add(n as u32), &r1, n);
        }
        x if x == MOD_MUL => {
            // (a0 + a1*X)(b0 + b1*X) = (a0 b0 - a1 b1) + (a0 b1 + a1 b0) X
            let r0_pre = &a0 * &b0;
            let r0_neg = &a1 * &b1;
            let r0 = if r0_pre >= r0_neg {
                (&r0_pre - &r0_neg) % p
            } else {
                let diff = &r0_neg - &r0_pre;
                let k = diff.div_ceil(p);
                ((k * p) + &r0_pre - &r0_neg) % p
            };
            let r1 = (&a0 * &b1 + &a1 * &b0) % p;
            write_le(cpu, out, &r0, n);
            write_le(cpu, out.wrapping_add(n as u32), &r1, n);
        }
        x if x == MOD_DIV => {
            // Need inverse of (b0 + b1 X). norm = b0^2 + b1^2.
            let norm = (&b0 * &b0 + &b1 * &b1) % p;
            let inv = mod_inv(&norm, p).ok_or_else(|| {
                CpuError::CustomOp(format!(
                    "complex div: non-invertible norm at pc=0x{:08x}",
                    cpu.pc
                ))
            })?;
            // b^{-1} = (b0 - b1 X) / norm
            let conj0 = b0.clone();
            let conj1 = if b1.is_zero() {
                BigUint::zero()
            } else {
                (p - &b1) % p
            };
            let inv0 = (&conj0 * &inv) % p;
            let inv1 = (&conj1 * &inv) % p;
            // Multiply a by b^{-1}.
            let r0_pre = &a0 * &inv0;
            let r0_neg = &a1 * &inv1;
            let r0 = if r0_pre >= r0_neg {
                (&r0_pre - &r0_neg) % p
            } else {
                let diff = &r0_neg - &r0_pre;
                let k = diff.div_ceil(p);
                ((k * p) + &r0_pre - &r0_neg) % p
            };
            let r1 = (&a0 * &inv1 + &a1 * &inv0) % p;
            write_le(cpu, out, &r0, n);
            write_le(cpu, out.wrapping_add(n as u32), &r1, n);
        }
        x if x == MOD_ISEQ => {
            // Same convention as modular IsEq — destination is the register
            // file, not memory.
            let eq = (a0 % p == b0 % p) && (a1 % p == b1 % p);
            cpu.write_reg(rd_idx, eq as u32);
        }
        x if x == MOD_SETUP => {
            tracing::trace!(name = entry.name, "COMPLEX_SETUP (noop)");
        }
        _ => {
            return Err(CpuError::CustomOp(format!(
                "unknown complex op={} for {} at pc=0x{:08x}",
                op, entry.name, cpu.pc
            )))
        }
    }
    Ok(())
}
