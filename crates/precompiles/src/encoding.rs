//! OpenVM custom-opcode encoding constants — extracted from upstream
//! `openvm-org/openvm` (matches the `v2.0.0-beta.2-powdr` fork used by this
//! workspace's parent).

#![allow(dead_code)]

// Opcode slots (RISC-V bits [6:0]).
pub const OPCODE_CUSTOM_0: u32 = 0x0b; // openvm "system" opcode — I/O, terminate, phantom, keccak, sha, int256
pub const OPCODE_CUSTOM_1: u32 = 0x2b; // openvm "extensions" opcode — modular, ecc, complex (Fp2), pairing

// ---- custom-0 funct3 ----
pub const F3_TERMINATE: u32 = 0b000;
pub const F3_HINT: u32 = 0b001;
pub const F3_REVEAL: u32 = 0b010;
pub const F3_PHANTOM: u32 = 0b011;
// The powdr-labs fork at v2-powdr-beta.2 (which `openvm-eth` patches in via
// its workspace [patch] section) uses LOW-LEVEL hash primitives on
// funct3=0b100, distinguished by funct7. The full keccak256/sha256 hashes
// are implemented in software by openvm-keccak256-guest /
// openvm-sha2-guest's wrapper functions, which call these in a loop.
pub const F3_HASH: u32 = 0b100;
pub const F7_KECCAKF: u32 = 0; // Keccak-f[1600] permutation on a 200-byte state
pub const F7_XORIN: u32 = 1; // XOR `len` bytes from [rs1] into [rd]
pub const F7_SHA256_COMPRESS: u32 = 2; // one SHA-256 compression: new_state ← compress(prev_state, 64-byte block)
pub const F7_SHA512_COMPRESS: u32 = 3; // SHA-512 compression
// Bigint 256 ops (Int256Funct7 maps add/sub/xor/or/and/sll/srl/sra/slt/sltu/mul).
pub const F3_INT256: u32 = 0b101;
// Branch-equal-256 (BEQ256_FUNCT3) — compares two 256-bit operands at rs1/rs2,
// taken if equal (branch offset in imm).
pub const F3_BEQ256: u32 = 0b110;
// Store-to-native — funct7 = 2, used only by openvm-internal native code.
pub const F3_NATIVE_STOREW: u32 = 0b111;

// ---- custom-0 hint imm values ----
pub const HINT_STOREW_IMM: u32 = 0;
pub const HINT_BUFFER_IMM: u32 = 1;

// ---- custom-0 phantom imm values (PhantomImm enum) ----
pub const PHANTOM_HINT_INPUT: u32 = 0;
pub const PHANTOM_PRINT_STR: u32 = 1;
pub const PHANTOM_HINT_RANDOM: u32 = 2;
pub const PHANTOM_HINT_LOAD_BY_KEY: u32 = 3;

// ---- custom-1 funct3 ----
pub const F3_MODULAR: u32 = 0b000;
pub const F3_SW: u32 = 0b001;
pub const F3_COMPLEX: u32 = 0b010;
pub const F3_PAIRING: u32 = 0b011;

// ---- modular arithmetic op (low bits of funct7) ----
pub const MODULAR_MAX_KINDS: u32 = 8;
pub const MOD_ADD: u32 = 0;
pub const MOD_SUB: u32 = 1;
pub const MOD_MUL: u32 = 2;
pub const MOD_DIV: u32 = 3;
pub const MOD_ISEQ: u32 = 4;
pub const MOD_SETUP: u32 = 5; // setup uses a special funct7 value; see openvm transpiler

// ---- complex extension (Fp2) ops — same kinds-per-field pattern as modular ----
pub const COMPLEX_MAX_KINDS: u32 = 8;
pub const COMPLEX_ADD: u32 = 0;
pub const COMPLEX_SUB: u32 = 1;
pub const COMPLEX_MUL: u32 = 2;
pub const COMPLEX_DIV: u32 = 3;
pub const COMPLEX_SETUP: u32 = 5;

// ---- short-Weierstrass ECC ops ----
pub const SW_MAX_KINDS: u32 = 8;
pub const SW_ADD_NE: u32 = 0;
pub const SW_DOUBLE: u32 = 1;
pub const SW_SETUP: u32 = 2;
pub const SW_HINT_DECOMPRESS: u32 = 3;
pub const SW_HINT_NON_QR: u32 = 4;

// ---- pairing ops ----
pub const PAIRING_MAX_KINDS: u32 = 16;
pub const PAIRING_HINT_FINAL_EXP: u32 = 0;
pub const PAIRING_MILLER_DOUBLE: u32 = 1;
pub const PAIRING_MILLER_DOUBLE_AND_ADD: u32 = 2;
pub const PAIRING_MILLER_LOOP: u32 = 3;

// ---- int256 (bigint) ops — Int256Funct7 enum, repr(u8) ----
pub const INT256_ADD: u32 = 0;
pub const INT256_SUB: u32 = 1;
pub const INT256_XOR: u32 = 2;
pub const INT256_OR: u32 = 3;
pub const INT256_AND: u32 = 4;
pub const INT256_SLL: u32 = 5;
pub const INT256_SRL: u32 = 6;
pub const INT256_SRA: u32 = 7;
pub const INT256_SLT: u32 = 8;
pub const INT256_SLTU: u32 = 9;
pub const INT256_MUL: u32 = 10;
