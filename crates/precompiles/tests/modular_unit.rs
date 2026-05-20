//! Sanity-check our modular arithmetic against `num_bigint::BigUint::modpow`
//! for the BN254 Fr modulus — the case that's exercised by the
//! `accelerated_modexp_bn254_fr` path in `openvm-revm-crypto`.

use num_bigint::BigUint;
use num_traits::Num;
use sim_elf::{LoadedProgram, Segment};
use sim_precompiles::PrecompileHandler;
use sim_rv32im::{Cpu, CustomOpHandler};

fn make_cpu(insn: u32) -> Cpu {
    let mut data = Vec::new();
    data.extend_from_slice(&insn.to_le_bytes());
    Cpu::new(&LoadedProgram {
        entry: 0x100,
        segments: vec![Segment {
            vaddr: 0x100,
            mem_size: 4,
            writable: false,
            executable: true,
            data,
        }],
    })
}

fn put_le(cpu: &mut Cpu, addr: u32, v: &BigUint, n: usize) {
    let mut bs = v.to_bytes_le();
    bs.resize(n, 0);
    for (i, b) in bs.iter().enumerate() {
        cpu.mem.write_u8(addr + i as u32, *b);
    }
}
fn get_le(cpu: &Cpu, addr: u32, n: usize) -> BigUint {
    BigUint::from_bytes_le(&cpu.mem.read_vec(addr, n))
}

/// Encode 0x2b funct3=0b000 (MODULAR) R-type with funct7 = mod_idx*8 + op,
/// rd=10, rs1=11, rs2=12.
fn enc_mod(mod_idx: u32, op: u32) -> u32 {
    let f7 = mod_idx * 8 + op;
    (f7 << 25) | (12 << 20) | (11 << 15) | (0b000 << 12) | (10 << 7) | 0x2b
}

fn modular_op(mod_idx: u32, op: u32, a: &BigUint, b: &BigUint, n: usize) -> BigUint {
    let insn = enc_mod(mod_idx, op);
    let mut cpu = make_cpu(insn);
    cpu.write_reg(10, 0x1000);
    cpu.write_reg(11, 0x2000);
    cpu.write_reg(12, 0x3000);
    put_le(&mut cpu, 0x2000, a, n);
    put_le(&mut cpu, 0x3000, b, n);
    let mut h = PrecompileHandler::new(Vec::new());
    h.handle(&mut cpu, insn).unwrap();
    get_le(&cpu, 0x1000, n)
}

fn bn254_fr() -> BigUint {
    BigUint::from_str_radix(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .unwrap()
}

#[test]
fn bn254_fr_add_zero() {
    let p = bn254_fr();
    let a = BigUint::from(12345u32);
    let r = modular_op(1, 0, &a, &BigUint::from(0u32), 32);
    assert_eq!(r, a);
    let r = modular_op(1, 0, &a, &(&p - 1u32), 32);
    assert_eq!(r, (a - 1u32) % &p);
}

#[test]
fn bn254_fr_mul_known() {
    let p = bn254_fr();
    let a = &p - BigUint::from(1u32); // -1 mod p
    let b = BigUint::from(2u32);
    let r = modular_op(1, 2, &a, &b, 32);
    // (-1) * 2 mod p = p - 2
    assert_eq!(r, &p - 2u32);
}

#[test]
fn bn254_fr_mul_random_vs_reference() {
    let p = bn254_fr();
    let a = BigUint::from_str_radix(
        "123456789012345678901234567890123456789012345678901234567890123456789012345678",
        10,
    )
    .unwrap()
        % &p;
    let b = BigUint::from_str_radix(
        "987654321098765432109876543210987654321098765432109876543210987654321098765432",
        10,
    )
    .unwrap()
        % &p;
    let expected = (&a * &b) % &p;
    let actual = modular_op(1, 2, &a, &b, 32);
    assert_eq!(actual, expected, "MulMod bn254_fr mismatch");
}

/// Exponentiate via repeated MulMod and squaring (matches what
/// `bn::Scalar::exp_bytes` does in the guest). Compare to BigUint::modpow.
#[test]
fn bn254_fr_modexp_vs_reference() {
    let p = bn254_fr();
    // Pick a random base/exp.
    let base = BigUint::from_str_radix(
        "5817253657439845634856734856734856734856734856734856734",
        10,
    )
    .unwrap()
        % &p;
    let exp = BigUint::from_str_radix("12345678901234567890", 10).unwrap();
    let expected = base.modpow(&exp, &p);

    // Compute base^exp via our MulMod handler in a left-to-right square-and-multiply loop.
    let mut acc = BigUint::from(1u32);
    let bits = format!("{:b}", exp);
    for ch in bits.chars() {
        acc = modular_op(1, 2, &acc, &acc, 32); // square
        if ch == '1' {
            acc = modular_op(1, 2, &acc, &base, 32); // multiply
        }
    }
    assert_eq!(acc, expected, "modexp bn254_fr divergence");
}
