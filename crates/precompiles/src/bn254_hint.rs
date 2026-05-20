//! BN254 `HintFinalExp` implementation using `ark-bn254`.
//!
//! See `pairing.rs` for the wire ABI. This module:
//! 1. reads G1/G2 inputs from guest memory
//! 2. computes the multi-Miller-loop output `f` in Fq12 via `ark_ec`
//! 3. computes `(c, u)` per the Gnark residue-witness algorithm so that
//!    `f * u = c^λ` (where λ = 6x+2+p-p²+p³, x = 4965661367192848881),
//!    `u ∈ {1, ω, ω²}` with ω = primitive 27-th root of unity in Fq12
//! 4. serialises `c` then `u` (each 12 × 32 = 384 bytes) and pushes them
//!    into the guest's hint stream

use crate::PrecompileHandler;
use ark_bn254::{Fq, Fq12, Fq2, Fq6, Fr, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ff::{BigInteger, PrimeField, Field, One, Zero};
use num_bigint::BigUint;
use num_traits::Num;
use sim_rv32im::{Cpu, CpuError};

// ----- byte <-> field helpers ------------------------------------------------

fn read_fq(cpu: &Cpu, addr: u32) -> Fq {
    let mut bs = [0u8; 32];
    for i in 0..32 {
        bs[i] = cpu.mem.read_u8(addr.wrapping_add(i as u32));
    }
    // halo2curves and openvm store Fq as 32 LE bytes of the canonical value.
    Fq::from_le_bytes_mod_order(&bs)
}

fn read_fq2(cpu: &Cpu, addr: u32) -> Fq2 {
    let c0 = read_fq(cpu, addr);
    let c1 = read_fq(cpu, addr.wrapping_add(32));
    Fq2::new(c0, c1)
}

fn fq_to_le_bytes(x: &Fq) -> [u8; 32] {
    let bi = x.into_bigint();
    let mut out = [0u8; 32];
    let bs = bi.to_bytes_le();
    let n = bs.len().min(32);
    out[..n].copy_from_slice(&bs[..n]);
    out
}

fn fq2_to_le_bytes(x: &Fq2) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&fq_to_le_bytes(&x.c0));
    out[32..].copy_from_slice(&fq_to_le_bytes(&x.c1));
    out
}

/// Serialise an Fq12 in OpenVM's order: [c0.c0, c1.c0, c0.c1, c1.c1, c0.c2, c1.c2]
/// where Fq12 = Fq6 + Fq6·w, Fq6 = Fq2 + Fq2·v + Fq2·v².
fn fq12_to_openvm_bytes(f: &Fq12) -> [u8; 384] {
    let order: [Fq2; 6] = [
        f.c0.c0, f.c1.c0, f.c0.c1, f.c1.c1, f.c0.c2, f.c1.c2,
    ];
    let mut out = [0u8; 384];
    for (i, c) in order.iter().enumerate() {
        out[i * 64..(i + 1) * 64].copy_from_slice(&fq2_to_le_bytes(c));
    }
    out
}

// ----- residue-witness algorithm --------------------------------------------

fn bigu(s: &str) -> BigUint {
    BigUint::from_str_radix(s, 10).expect("decimal literal")
}

/// EXP1 = (p^12 - 1) / 3
fn exp1() -> BigUint {
    bigu("4030969696062745741797811005853058291874379204406359442560681893891674450106959530046539719647151210908190211459382793062006703141168852426020468083171325367934590379984666859998399967609544754664110191464072930598755441160008826659219834762354786403012110463250131961575955268597858015384895449311534622125256548620283853223733396368939858981844663598065852816056384933498610930035891058807598891752166582271931875150099691598048016175399382213304673796601585080509443902692818733420199004555566113537482054218823936116647313678747500267068559627206777530424029211671772692598157901876223857571299238046741502089890557442500582300718504160740314926185458079985126192563953772118929726791041828902047546977272656240744693339962973939047279285351052107950250121751682659529260304162131862468322644288196213423232132152125277136333208005221619443705106431645884840489295409272576227859206166894626854018093044908314720")
}

/// EXP2 = (s + 1) / 3   where p^12 - 1 = 3^3 · s
fn exp2() -> BigUint {
    bigu("149295173928249842288807815031594751550902933496531831205951181255247201855813315927649619246190785589192230054051214557852100116339587126889646966043382421034614458517950624444385183985538694617189266350521219651805757080000326913304438324531658755667115202342597480058368713651772519088329461085612393412046538837788290860138273939590365147475728281409846400594680923462911515927255224400281440435265428973034513894448136725853630228718495637529802733207466114092942366766400693830377740909465411612499335341437923559875826432546203713595131838044695464089778859691547136762894737106526809539677749557286722299625576201574095640767352005953344997266128077036486155280146436004404804695964512181557316554713802082990544197776406442186936269827816744738898152657469728130713344598597476387715653492155415311971560450078713968012341037230430349766855793764662401499603533676762082513303932107208402000670112774382027")
}

/// r_inv = 1/r mod (p^12 - 1)/r
fn r_inv() -> BigUint {
    bigu("495819184011867778744231927046742333492451180917315223017345540833046880485481720031136878341141903241966521818658471092566752321606779256340158678675679238405722886654128392203338228575623261160538734808887996935946888297414610216445334190959815200956855428635568184508263913274453942864817234480763055154719338281461936129150171789463489422401982681230261920147923652438266934726901346095892093443898852488218812468761027620988447655860644584419583586883569984588067403598284748297179498734419889699245081714359110559679136004228878808158639412436468707589339209058958785568729925402190575720856279605832146553573981587948304340677613460685405477047119496887534881410757668344088436651291444274840864486870663164657544390995506448087189408281061890434467956047582679858345583941396130713046072603335601764495918026585155498301896749919393")
}

/// m_inv = 1/m mod p^12 - 1   where m = λ / (3·r)
fn m_inv() -> BigUint {
    bigu("17840267520054779749190587238017784600702972825655245554504342129614427201836516118803396948809179149954197175783449826546445899524065131269177708416982407215963288737761615699967145070776364294542559324079147363363059480104341231360692143673915822421222230661528586799190306058519400019024762424366780736540525310403098758015600523609594113357130678138304964034267260758692953579514899054295817541844330584721967571697039986079722203518034173581264955381924826388858518077894154909963532054519350571947910625755075099598588672669612434444513251495355121627496067454526862754597351094345783576387352673894873931328099247263766690688395096280633426669535619271711975898132416216382905928886703963310231865346128293216316379527200971959980873989485521004596686352787540034457467115536116148612884807380187255514888720048664139404687086409399")
}

/// A primitive 27th root of unity in Fq12, embedded via the openvm convention:
///     unity_root_27 = u_coeffs · v   (i.e. coefficient at index 2 in the
///     `[c0.c0, c1.c0, c0.c1, c1.c1, c0.c2, c1.c2]` flattening — that lands
///     in Fq6.c1 of the Fq12 LOW half).
fn unity_root_27() -> Fq12 {
    let u0 = bigu("9483667112135124394372960210728142145589475128897916459350428495526310884707");
    let u1 = bigu("4534159768373982659291990808346042891252278737770656686799127720849666919525");
    let u_c0 = Fq::from_le_bytes_mod_order(&u0.to_bytes_le());
    let u_c1 = Fq::from_le_bytes_mod_order(&u1.to_bytes_le());
    let u_coeffs = Fq2::new(u_c0, u_c1);
    // OpenVM constructed Fq12 with `from_coeffs([0,0,u_coeffs,0,0,0])`. The
    // from_coeffs flattening maps coeffs[0..6] → (c0=(c0.c0,c0.c1,c0.c2),
    // c1=(c1.c0,c1.c1,c1.c2)) as [c0.c0,c1.c0,c0.c1,c1.c1,c0.c2,c1.c2].
    // So u_coeffs at index 2 means it's c0.c1.
    let c0 = Fq6::new(Fq2::zero(), u_coeffs, Fq2::zero());
    let c1 = Fq6::zero();
    Fq12::new(c0, c1)
}

fn pow_biguint(base: &Fq12, exp: &BigUint) -> Fq12 {
    // BigUint::to_u64_digits returns little-endian limbs — exactly what
    // Field::pow expects.
    base.pow(exp.to_u64_digits())
}

/// Port of `final_exp_hint` from the openvm halo2curves shim.
fn final_exp_hint(f: &Fq12) -> (Fq12, Fq12) {
    let one = Fq12::one();
    let unity_root_27 = unity_root_27();
    debug_assert_eq!(unity_root_27.pow([27u64]), one);

    let e1 = exp1();
    let (mut c, u) = {
        if pow_biguint(f, &e1) == one {
            (*f, Fq12::one())
        } else {
            let fu = *f * unity_root_27;
            if pow_biguint(&fu, &e1) == one {
                (fu, unity_root_27)
            } else {
                (fu * unity_root_27, unity_root_27 * unity_root_27)
            }
        }
    };

    // r-th root, then m-th root.
    c = pow_biguint(&c, &r_inv());
    c = pow_biguint(&c, &m_inv());

    // Modified Tonelli–Shanks for the cube root.
    let e2 = exp2();
    let unity_root_27_exp2 = pow_biguint(&unity_root_27, &e2);
    let mut x = pow_biguint(&c, &e2);

    let c_inv = c.inverse().expect("c is nonzero");
    let mut x3 = x * x * x * c_inv;
    let mut t = 0i32;
    let mut tmp;
    fn ts_loop(x3: &mut Fq12, tmp: &mut Fq12, t: &mut i32) {
        let one = Fq12::one();
        while *x3 != one {
            *tmp = *x3 * *x3;
            *x3 *= *tmp;
            *t += 1;
        }
    }
    tmp = x3 * x3;
    ts_loop(&mut x3, &mut tmp, &mut t);
    while t != 0 {
        x *= unity_root_27_exp2;
        x3 = x * x * x * c_inv;
        t = 0;
        tmp = x3 * x3;
        ts_loop(&mut x3, &mut tmp, &mut t);
    }
    debug_assert_eq!(c, x * x * x);
    c = x;

    (c, u)
}

// ----- top-level handler -----------------------------------------------------

pub fn hint_final_exp(
    h: &mut PrecompileHandler,
    cpu: &mut Cpu,
    insn: u32,
) -> Result<(), CpuError> {
    // rs1/rs2 each holds the address of an 8-byte (ptr, len) descriptor.
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
            "BN254 HintFinalExp: P/Q length mismatch ({} vs {}) at pc=0x{:08x}",
            p_len, q_len, cpu.pc
        )));
    }
    if p_len == 0 {
        // Empty multi-miller-loop has f = 1; emit (c=1, u=1).
        let one = Fq12::one();
        let bytes = fq12_to_openvm_bytes(&one);
        for b in &bytes {
            h.io.hint_stream.push_back(*b);
        }
        for b in &bytes {
            h.io.hint_stream.push_back(*b);
        }
        return Ok(());
    }

    let mut g1_pts = Vec::with_capacity(p_len as usize);
    let mut g2_pts = Vec::with_capacity(q_len as usize);
    for i in 0..p_len {
        let base = p_ptr.wrapping_add(i * 64);
        let x = read_fq(cpu, base);
        let y = read_fq(cpu, base.wrapping_add(32));
        // We trust the guest to have on-curve inputs; new_unchecked skips
        // the y² == x³ + 3 check.
        g1_pts.push(G1Affine::new_unchecked(x, y));
    }
    for i in 0..q_len {
        let base = q_ptr.wrapping_add(i * 128);
        let x = read_fq2(cpu, base);
        let y = read_fq2(cpu, base.wrapping_add(64));
        g2_pts.push(G2Affine::new_unchecked(x, y));
    }

    // Multi-Miller-loop. ark-bn254's Pairing impl handles all the line/step
    // bookkeeping for us.
    let f = ark_bn254::Bn254::multi_miller_loop(g1_pts.iter().copied(), g2_pts.iter().copied()).0;
    let (c, u) = final_exp_hint(&f);

    // Push c then u into the hint stream.
    let c_bytes = fq12_to_openvm_bytes(&c);
    for b in &c_bytes {
        h.io.hint_stream.push_back(*b);
    }
    let u_bytes = fq12_to_openvm_bytes(&u);
    for b in &u_bytes {
        h.io.hint_stream.push_back(*b);
    }

    Ok(())
}

// Silence "unused" warnings if the optional Fr import lands here from a
// future tower-arithmetic refactor.
#[allow(dead_code)]
fn _unused(_: Fr) {}
