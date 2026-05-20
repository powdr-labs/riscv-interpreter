//! Short-Weierstrass ECC precompiles (opcode 0x2b, funct3=0b001).
//!
//! Encoding: `funct7 = curve_idx * 8 + base_op` where
//!   0 = AddNe (P+Q with P.x != Q.x)
//!   1 = Double
//!   2 = Setup (no-op for us)
//!   3 = HintDecompress
//!   4 = HintNonQr
//!
//! Each affine point on the wire is `coord_bytes` × 2 bytes, little-endian:
//! `x_le || y_le`.

use crate::config::CurveEntry;
use crate::encoding::{SW_ADD_NE, SW_DOUBLE, SW_HINT_DECOMPRESS, SW_HINT_NON_QR, SW_MAX_KINDS, SW_SETUP};
use crate::{rd, rs1, rs2, PrecompileHandler};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};
use sim_rv32im::{Cpu, CpuError};

fn read_le(cpu: &Cpu, ptr: u32, n: usize) -> BigUint {
    BigUint::from_bytes_le(&cpu.mem.read_vec(ptr, n))
}
fn write_le(cpu: &mut Cpu, ptr: u32, val: &BigUint, n: usize) {
    let mut bs = val.to_bytes_le();
    bs.resize(n, 0);
    for (i, b) in bs.iter().enumerate() {
        cpu.mem.write_u8(ptr.wrapping_add(i as u32), *b);
    }
}

fn read_point(cpu: &Cpu, ptr: u32, n: usize) -> (BigUint, BigUint) {
    let x = read_le(cpu, ptr, n);
    let y = read_le(cpu, ptr.wrapping_add(n as u32), n);
    (x, y)
}
fn write_point(cpu: &mut Cpu, ptr: u32, p: &(BigUint, BigUint), n: usize) {
    write_le(cpu, ptr, &p.0, n);
    write_le(cpu, ptr.wrapping_add(n as u32), &p.1, n);
}

fn mod_inv(a: &BigUint, p: &BigUint) -> Option<BigUint> {
    use num_bigint::BigInt;
    if a.is_zero() {
        return None;
    }
    let (g, x, _) = ext_gcd(BigInt::from(a.clone()), BigInt::from(p.clone()));
    if g != BigInt::from(1u32) {
        None
    } else {
        let p_i = BigInt::from(p.clone());
        let inv = ((x % &p_i) + &p_i) % &p_i;
        Some(inv.to_biguint().unwrap())
    }
}
fn ext_gcd(
    a: num_bigint::BigInt,
    b: num_bigint::BigInt,
) -> (num_bigint::BigInt, num_bigint::BigInt, num_bigint::BigInt) {
    use num_bigint::BigInt;
    use num_traits::Zero;
    if b.is_zero() {
        (a, BigInt::from(1u32), BigInt::zero())
    } else {
        let (g, x1, y1) = ext_gcd(b.clone(), &a % &b);
        let x = y1.clone();
        let y = x1 - (&a / &b) * y1;
        (g, x, y)
    }
}

fn modp_sub(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    let a = a % p;
    let b = b % p;
    if a >= b {
        (a - b) % p
    } else {
        (p + a - b) % p
    }
}

fn add_ne(curve: &CurveEntry, p1: &(BigUint, BigUint), p2: &(BigUint, BigUint)) -> (BigUint, BigUint) {
    let p = &curve.modulus;
    let dx = modp_sub(&p2.0, &p1.0, p);
    let dy = modp_sub(&p2.1, &p1.1, p);
    let inv_dx = mod_inv(&dx, p).expect("AddNe with equal x");
    let lam = (&dy * &inv_dx) % p;
    let lam_sq = (&lam * &lam) % p;
    let x3 = modp_sub(&modp_sub(&lam_sq, &p1.0, p), &p2.0, p);
    let y3 = modp_sub(&((&lam * &modp_sub(&p1.0, &x3, p)) % p), &p1.1, p);
    (x3, y3)
}

fn double(curve: &CurveEntry, p1: &(BigUint, BigUint)) -> (BigUint, BigUint) {
    let p = &curve.modulus;
    let three = BigUint::from(3u32);
    let two = BigUint::from(2u32);
    let x_sq = (&p1.0 * &p1.0) % p;
    let num = (&three * &x_sq + &curve.a) % p;
    let den = (&two * &p1.1) % p;
    let inv_den = mod_inv(&den, p).expect("Double of point with y=0");
    let lam = (&num * &inv_den) % p;
    let lam_sq = (&lam * &lam) % p;
    let two_x = (&two * &p1.0) % p;
    let x3 = modp_sub(&lam_sq, &two_x, p);
    let y3 = modp_sub(&((&lam * &modp_sub(&p1.0, &x3, p)) % p), &p1.1, p);
    (x3, y3)
}

/// Tonelli–Shanks square root mod p. Returns one of the two roots (the
/// canonical-positive one). Caller may negate to get the other parity.
fn tonelli_shanks(n: &BigUint, p: &BigUint) -> Option<BigUint> {
    if n.is_zero() {
        return Some(BigUint::zero());
    }
    // Euler's criterion: n^((p-1)/2) == 1
    let pm1 = p - 1u32;
    let half = &pm1 >> 1;
    if n.modpow(&half, p) != BigUint::one() {
        return None;
    }
    // Factor p-1 = q * 2^s with q odd.
    let mut s = 0u32;
    let mut q = pm1.clone();
    while q.is_even() {
        q >>= 1;
        s += 1;
    }
    // Find a non-residue z.
    let mut z = BigUint::from(2u32);
    while z.modpow(&half, p) != &pm1 % p {
        z += 1u32;
    }
    let mut m = s;
    let mut c = z.modpow(&q, p);
    let exp = (&q + 1u32) >> 1;
    let mut t = n.modpow(&q, p);
    let mut r = n.modpow(&exp, p);
    loop {
        if t == BigUint::one() {
            return Some(r);
        }
        // Smallest i: 0 < i < m with t^(2^i) == 1
        let mut i = 0u32;
        let mut tmp = t.clone();
        while tmp != BigUint::one() {
            tmp = (&tmp * &tmp) % p;
            i += 1;
            if i == m {
                return None; // not a QR
            }
        }
        let b = c.modpow(&BigUint::from(1u32 << (m - i - 1)), p);
        m = i;
        c = (&b * &b) % p;
        t = (&t * &c) % p;
        r = (&r * &b) % p;
    }
}

pub fn handle_sw(h: &mut PrecompileHandler, cpu: &mut Cpu, insn: u32) -> Result<(), CpuError> {
    let f7 = (insn >> 25) & 0x7f;
    let idx = (f7 / SW_MAX_KINDS) as usize;
    let op = f7 % SW_MAX_KINDS;
    let curve = h.curves.get(idx).ok_or_else(|| {
        CpuError::CustomOp(format!(
            "SW: curve_idx {} out of range (have {}) at pc=0x{:08x}",
            idx,
            h.curves.len(),
            cpu.pc
        ))
    })?.clone();

    let n = curve.coord_bytes;
    let out = cpu.read_reg(rd(insn));
    let a_ptr = cpu.read_reg(rs1(insn));
    let b_ptr = cpu.read_reg(rs2(insn));

    match op {
        x if x == SW_ADD_NE => {
            let p1 = read_point(cpu, a_ptr, n);
            let p2 = read_point(cpu, b_ptr, n);
            let r = add_ne(&curve, &p1, &p2);
            write_point(cpu, out, &r, n);
        }
        x if x == SW_DOUBLE => {
            let p1 = read_point(cpu, a_ptr, n);
            let r = double(&curve, &p1);
            write_point(cpu, out, &r, n);
        }
        x if x == SW_SETUP => {
            tracing::trace!(curve = curve.name, "SW_SETUP (noop)");
        }
        x if x == SW_HINT_DECOMPRESS => {
            // Input: x (n bytes) at rs1, parity-byte at rs2.
            // Output: y (n bytes) at rd.
            let x = read_le(cpu, a_ptr, n);
            let parity = cpu.read_reg(rs2(insn)) & 1;
            let x_sq = (&x * &x) % &curve.modulus;
            let x_cu = (&x_sq * &x) % &curve.modulus;
            let ax = (&curve.a * &x) % &curve.modulus;
            let rhs = (x_cu + ax + &curve.b) % &curve.modulus;
            let y = tonelli_shanks(&rhs, &curve.modulus).ok_or_else(|| {
                CpuError::CustomOp(format!(
                    "SW HintDecompress: no sqrt for x on {} at pc=0x{:08x}",
                    curve.name, cpu.pc
                ))
            })?;
            let y_parity = (&y % 2u32) != BigUint::zero();
            let final_y = if (y_parity as u32) == parity {
                y
            } else {
                &curve.modulus - y
            };
            write_le(cpu, out, &final_y, n);
        }
        x if x == SW_HINT_NON_QR => {
            // Output a non-quadratic residue mod p. Compute once and write.
            let mut z = BigUint::from(2u32);
            let pm1 = &curve.modulus - 1u32;
            let half = &pm1 >> 1;
            while z.modpow(&half, &curve.modulus) != &pm1 % &curve.modulus {
                z += 1u32;
            }
            write_le(cpu, out, &z, n);
        }
        _ => {
            return Err(CpuError::CustomOp(format!(
                "unknown SW op={} curve={} at pc=0x{:08x}",
                op, curve.name, cpu.pc
            )))
        }
    }
    Ok(())
}
