//! BLS12-381 `HintFinalExp` (opcode 0x2b, funct3=0b011, funct7=pairing_idx·16).
//!
//! Wire ABI mirrors BN254's:
//! - `rs1` → `{p_ptr: u32, p_len: u32}` for G1 affine points (each Fq is 48 LE
//!   bytes, point = 96 bytes `x ‖ y`).
//! - `rs2` → `{q_ptr: u32, q_len: u32}` for G2 affine points (each Fq2 is
//!   2·48 = 96 LE bytes, point = 192 bytes `x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1`).
//! - Output: `c` then `s` in Fp12 (12·Fq elements each; 12·48 = 576 bytes per
//!   element; 1152 bytes total) pushed to `hint_stream`.
//!
//! Algorithm transcribed from
//! `extensions/pairing/guest/src/halo2curves_shims/bls12_381/{curve,final_exp}.rs`.

use crate::PrecompileHandler;
use ark_bls12_381::{Bls12_381, Fq, Fq12, Fq2, Fq6, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ff::{BigInteger, Field, One, PrimeField};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::Num;
use sim_rv32im::{Cpu, CpuError};

// ----- byte <-> field helpers ------------------------------------------------

fn read_fq(cpu: &Cpu, addr: u32) -> Fq {
    let mut bs = [0u8; 48];
    for i in 0..48 {
        bs[i] = cpu.mem.read_u8(addr.wrapping_add(i as u32));
    }
    Fq::from_le_bytes_mod_order(&bs)
}
fn read_fq2(cpu: &Cpu, addr: u32) -> Fq2 {
    let c0 = read_fq(cpu, addr);
    let c1 = read_fq(cpu, addr.wrapping_add(48));
    Fq2::new(c0, c1)
}

fn fq_to_le48(x: &Fq) -> [u8; 48] {
    let bi = x.into_bigint();
    let mut out = [0u8; 48];
    let bs = bi.to_bytes_le();
    let n = bs.len().min(48);
    out[..n].copy_from_slice(&bs[..n]);
    out
}
fn fq2_to_le(x: &Fq2) -> [u8; 96] {
    let mut out = [0u8; 96];
    out[..48].copy_from_slice(&fq_to_le48(&x.c0));
    out[48..].copy_from_slice(&fq_to_le48(&x.c1));
    out
}
/// Serialise Fq12 in openvm's `[c0.c0, c1.c0, c0.c1, c1.c1, c0.c2, c1.c2]`
/// flattening order.
fn fq12_to_openvm_bytes(f: &Fq12) -> [u8; 576] {
    let order: [Fq2; 6] = [
        f.c0.c0, f.c1.c0, f.c0.c1, f.c1.c1, f.c0.c2, f.c1.c2,
    ];
    let mut out = [0u8; 576];
    for (i, c) in order.iter().enumerate() {
        out[i * 96..(i + 1) * 96].copy_from_slice(&fq2_to_le(c));
    }
    out
}

// ----- residue-witness constants (verbatim from openvm) ---------------------

fn bigu(s: &str) -> BigUint {
    BigUint::from_str_radix(s, 10).expect("decimal literal")
}

fn poly_factor() -> BigUint {
    bigu("5044125407647214251")
}
fn final_exp_factor() -> BigUint {
    bigu("2366356426548243601069753987687709088104621721678962410379583120840019275952471579477684846670499039076873213559162845121989217658133790336552276567078487633052653005423051750848782286407340332979263075575489766963251914185767058009683318020965829271737924625612375201545022326908440428522712877494557944965298566001441468676802477524234094954960009227631543471415676620753242466901942121887152806837594306028649150255258504417829961387165043999299071444887652375514277477719817175923289019181393803729926249507024121957184340179467502106891835144220611408665090353102353194448552304429530104218473070114105759487413726485729058069746063140422361472585604626055492939586602274983146215294625774144156395553405525711143696689756441298365274341189385646499074862712688473936093315628166094221735056483459332831845007196600723053356837526749543765815988577005929923802636375670820616189737737304893769679803809426304143627363860243558537831172903494450556755190448279875942974830469855835666815454271389438587399739607656399812689280234103023464545891697941661992848552456326290792224091557256350095392859243101357349751064730561345062266850238821755009430903520645523345000326783803935359711318798844368754833295302563158150573540616830138810935344206231367357992991289265295323280")
}
fn lambda() -> BigUint {
    bigu("4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129030796414117214202539")
}

fn pow_bu(base: &Fq12, exp: &BigUint) -> Fq12 {
    base.pow(exp.to_u64_digits())
}
fn inv_pow_bu(base: &Fq12, exp: &BigUint) -> Fq12 {
    base.inverse().expect("nonzero").pow(exp.to_u64_digits())
}

fn final_exp_hint(f: &Fq12) -> (Fq12, Fq12) {
    let one = Fq12::one();
    let p = final_exp_factor();
    let r27 = BigUint::from(27u32);
    let r10 = BigUint::from(10u32);
    let poly = poly_factor();

    // FINAL_EXP_TIMES_27 = p * 27;  FINAL_EXP_TIMES_27_MOD_POLY = (p*27)^(-1) mod poly_factor
    let times27 = &p * &r27;
    let times27_mod_poly =
        times27.modinv(&poly).expect("inverse exists") % &poly;

    let f_final_exp = pow_bu(f, &p);

    // 1. p-th root inverse
    let root = pow_bu(&f_final_exp, &r27);
    let root_pth_inv = if root == one {
        one
    } else {
        inv_pow_bu(&root, &times27_mod_poly)
    };

    // 2. 27-th root inverse
    let root = pow_bu(&f_final_exp, &poly);
    let root_27th_inv = if pow_bu(&root, &r27) == one {
        inv_pow_bu(&root, &r10)
    } else {
        one
    };

    let s = root_pth_inv * root_27th_inv;
    let f_shifted = *f * s;

    // 3. residue witness: c = f_shifted ^ (1/lambda mod final_exp_factor)
    let lambda_inv = lambda().modinv(&p).expect("inverse exists");
    let c = pow_bu(&f_shifted, &lambda_inv);

    (c, s)
}

// ----- top-level handler -----------------------------------------------------

pub fn hint_final_exp(
    h: &mut PrecompileHandler,
    cpu: &mut Cpu,
    insn: u32,
) -> Result<(), CpuError> {
    let rs1 = (insn >> 15) & 0x1f;
    let rs2 = (insn >> 20) & 0x1f;
    let desc_p = cpu.read_reg(rs1);
    let desc_q = cpu.read_reg(rs2);
    let p_ptr = cpu.mem.read_u32(desc_p);
    let p_len = cpu.mem.read_u32(desc_p.wrapping_add(4));
    let q_ptr = cpu.mem.read_u32(desc_q);
    let q_len = cpu.mem.read_u32(desc_q.wrapping_add(4));

    if p_len != q_len {
        return Err(CpuError::CustomOp(format!(
            "BLS12-381 HintFinalExp: P/Q length mismatch ({} vs {}) at pc=0x{:08x}",
            p_len, q_len, cpu.pc
        )));
    }
    if p_len == 0 {
        let one = Fq12::one();
        let bytes = fq12_to_openvm_bytes(&one);
        for b in bytes.iter().chain(bytes.iter()) {
            h.io.hint_stream.push_back(*b);
        }
        return Ok(());
    }

    let mut g1_pts = Vec::with_capacity(p_len as usize);
    let mut g2_pts = Vec::with_capacity(q_len as usize);
    for i in 0..p_len {
        let base = p_ptr.wrapping_add(i * 96);
        let x = read_fq(cpu, base);
        let y = read_fq(cpu, base.wrapping_add(48));
        g1_pts.push(G1Affine::new_unchecked(x, y));
    }
    for i in 0..q_len {
        let base = q_ptr.wrapping_add(i * 192);
        let x = read_fq2(cpu, base);
        let y = read_fq2(cpu, base.wrapping_add(96));
        g2_pts.push(G2Affine::new_unchecked(x, y));
    }

    let f = Bls12_381::multi_miller_loop(g1_pts.iter().copied(), g2_pts.iter().copied()).0;
    let (c, s) = final_exp_hint(&f);

    // Push c then s into the hint stream.
    for b in fq12_to_openvm_bytes(&c).iter() {
        h.io.hint_stream.push_back(*b);
    }
    for b in fq12_to_openvm_bytes(&s).iter() {
        h.io.hint_stream.push_back(*b);
    }
    Ok(())
}

// Silence the unused-import warning when only the bigint hint paths are
// exercised.
#[allow(dead_code)]
fn _unused(_: Fq6, _: ()) {}
