//! Compile-time configuration of moduli, curves and pairings — mirrors the
//! contents of `bin/stateless-guest/openvm.toml` so that `mod_idx`,
//! `curve_idx`, etc. line up with what the guest emits.

use num_bigint::BigUint;
use num_traits::Num;

/// One modulus registered at boot (the guest's `mod_idx` is its position in
/// this vec).
#[derive(Debug, Clone)]
pub struct ModulusEntry {
    pub name: &'static str,
    pub limb_bytes: usize, // operand width in bytes
    pub modulus: BigUint,
}

/// Curve config for a Short-Weierstrass curve (y^2 = x^3 + a x + b mod p).
#[derive(Debug, Clone)]
pub struct CurveEntry {
    pub name: &'static str,
    pub coord_bytes: usize, // one coordinate's byte width
    pub modulus: BigUint,   // p (coordinate field)
    pub a: BigUint,
    pub b: BigUint,
}

fn dec(s: &str) -> BigUint {
    BigUint::from_str_radix(s, 10).expect("decimal modulus literal")
}

/// Built-in set matching `bin/stateless-guest/openvm.toml`. Order matters:
/// the index is the `mod_idx` the guest will encode in funct7.
pub fn default_moduli() -> Vec<ModulusEntry> {
    vec![
        ModulusEntry {
            name: "bn254_fp",
            limb_bytes: 32,
            modulus: dec("21888242871839275222246405745257275088696311157297823662689037894645226208583"),
        },
        ModulusEntry {
            name: "bn254_fr",
            limb_bytes: 32,
            modulus: dec("21888242871839275222246405745257275088548364400416034343698204186575808495617"),
        },
        ModulusEntry {
            name: "secp256k1_fp",
            limb_bytes: 32,
            modulus: dec("115792089237316195423570985008687907853269984665640564039457584007908834671663"),
        },
        ModulusEntry {
            name: "secp256k1_fr",
            limb_bytes: 32,
            modulus: dec("115792089237316195423570985008687907852837564279074904382605163141518161494337"),
        },
        ModulusEntry {
            name: "p256_fp",
            limb_bytes: 32,
            modulus: dec("115792089210356248762697446949407573530086143415290314195533631308867097853951"),
        },
        ModulusEntry {
            name: "p256_fr",
            limb_bytes: 32,
            modulus: dec("115792089210356248762697446949407573529996955224135760342422259061068512044369"),
        },
        ModulusEntry {
            name: "bls12_381_fp",
            limb_bytes: 48,
            modulus: dec("4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787"),
        },
        ModulusEntry {
            name: "bls12_381_fr",
            limb_bytes: 32,
            modulus: dec("52435875175126190479447740508185965837690552500527637822603658699938581184513"),
        },
    ]
}

/// Curve table — order matches `[[app_vm_config.ecc.supported_curves]]` in
/// the guest's openvm.toml.
pub fn default_curves() -> Vec<CurveEntry> {
    vec![
        CurveEntry {
            name: "bn254_g1",
            coord_bytes: 32,
            modulus: dec("21888242871839275222246405745257275088696311157297823662689037894645226208583"),
            a: BigUint::from(0u32),
            b: BigUint::from(3u32),
        },
        CurveEntry {
            name: "secp256k1",
            coord_bytes: 32,
            modulus: dec("115792089237316195423570985008687907853269984665640564039457584007908834671663"),
            a: BigUint::from(0u32),
            b: BigUint::from(7u32),
        },
        CurveEntry {
            name: "p256",
            coord_bytes: 32,
            modulus: dec("115792089210356248762697446949407573530086143415290314195533631308867097853951"),
            a: dec("115792089210356248762697446949407573530086143415290314195533631308867097853948"),
            b: dec("41058363725152142129326129780047268409114441015993725554835256314039467401291"),
        },
        CurveEntry {
            name: "bls12_381_g1",
            coord_bytes: 48,
            modulus: dec("4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787"),
            a: BigUint::from(0u32),
            b: BigUint::from(4u32),
        },
    ]
}

/// Complex (Fp2) table — `complex_init!` order in openvm_init.rs.
/// (Bn254Fp2 idx=0, Bls12_381Fp2 idx=1.) Each entry stores the base-field
/// modulus and limb width.
pub fn default_complex() -> Vec<ModulusEntry> {
    vec![
        ModulusEntry {
            name: "bn254_fp2",
            limb_bytes: 32,
            modulus: dec("21888242871839275222246405745257275088696311157297823662689037894645226208583"),
        },
        ModulusEntry {
            name: "bls12_381_fp2",
            limb_bytes: 48,
            modulus: dec("4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787"),
        },
    ]
}

/// Pairings — order in `app_vm_config.pairing.supported_curves`.
pub fn default_pairings() -> Vec<&'static str> {
    vec!["bn254", "bls12_381"]
}
