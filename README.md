# openvm-sim — Decoupled RISC-V Interpreter for OpenVM Guests

A standalone Cargo workspace that runs OpenVM-compiled RV32IM ELFs without
depending on any `openvm-*` crate. The interpreter recognises the full set
of OpenVM custom opcodes (custom-0 / custom-1, `0x0b` and `0x2b`) and
implements their semantics in pure Rust using vetted crypto libraries.

The goal: experiment with the same guest binaries `openvm-eth` proves, but
for execution only — no STARK, no SNARK, no autoprecompiles (APC).

## What's in here

```
/
├── Cargo.toml                 # Independent [workspace] — not part of openvm-eth
├── crates/
│   ├── elf/                   # rv32 ELF loader (no openvm dep)
│   ├── rv32im/                # RV32IM CPU + paged memory (no openvm dep)
│   ├── precompiles/           # Custom-opcode dispatcher (no openvm dep)
│   └── runner/                # CLI `openvm-sim` (no openvm dep)
├── tests/
│   └── fixtures/
│       ├── echo-guest/        # Round-trips bytes via HINT/REVEAL
│       └── hash-guest/        # Verifies Keccak-f + SHA-256-compress
└── tools/
    └── input-prep/            # ↳ DOES depend on openvm — bincode→hint-stream
```

## Encoding correctness — this fork vs upstream openvm

This codebase targets the **powdr-labs/openvm `v2-powdr-beta.2` fork** (the
parent workspace pins it via `[patch]`). That fork differs from upstream
openvm-org/openvm in a few critical ways that took experimentation to
discover:

| Slot | Upstream openvm-org/openvm | powdr-labs fork (what this sim handles) |
|---|---|---|
| `0x0b` funct3=0b100, funct7=0 | full `keccak256(bytes, len)` | **Keccak-f[1600] permutation** on a 200-byte state |
| `0x0b` funct3=0b100, funct7=1 | full `sha256(bytes, len)` | **XORIN** — XOR `len` bytes from `[rs1]` into `[rd]` |
| `0x0b` funct3=0b100, funct7=2 | (unused) | **SHA-256 compression** — `new_state ← compress(prev_state, 64-byte block)` |
| `0x0b` funct3=0b100, funct7=3 | (unused) | SHA-512 compression |
| `0x2b` funct3=0b000, funct7=mod_idx·8 + 6 | (unused) | **HintNonQr** — pushes a non-QR mod p into hint_stream |
| `0x2b` funct3=0b000, funct7=mod_idx·8 + 7 | (unused) | **HintSqrt** — pushes (is_qr flag, sqrt) for the value at `[rs1]` |
| `0x2b` funct3=0b000 IsEq result destination | memory at `[rd]` | **register rd** |

Full encoding table:

| Opcode | funct3 | Purpose | Status |
|---|---|---|---|
| `0x0b` (custom-0) | 0b000 | TERMINATE | ✅ |
| `0x0b` | 0b001 | HINT_STOREW / HINT_BUFFER | ✅ |
| `0x0b` | 0b010 | REVEAL | ✅ |
| `0x0b` | 0b011 | PHANTOM (HintInput w/ u32-length prefix, PrintStr, …) | ✅ |
| `0x0b` | 0b100, funct7=0 | KECCAK-f[1600] | ✅ |
| `0x0b` | 0b100, funct7=1 | XORIN | ✅ |
| `0x0b` | 0b100, funct7=2 | SHA-256 compress | ✅ |
| `0x0b` | 0b101 | INT256 (add/sub/xor/or/and/sll/srl/sra/slt/sltu/mul) | ✅ |
| `0x0b` | 0b110 | BEQ256 | ✅ |
| `0x0b` | 0b111 | NATIVE_STOREW | no-op (host-internal) |
| `0x2b` (custom-1) | 0b000 | Modular add/sub/mul/div/iseq/setup/hintnonqr/hintsqrt (8 moduli) | ✅ |
| `0x2b` | 0b001 | Short-Weierstrass ECC add/double/setup (4 curves) | ✅ |
| `0x2b` | 0b010 | Complex Fp2 add/sub/mul/div (BN254, BLS12-381) | ✅ |
| `0x2b` | 0b011 | BN254 + BLS12-381 pairing `HintFinalExp` (multi-Miller + residue witness via `ark-bn254` / `ark-bls12-381`) | ✅ |

## I/O ABI (matches openvm-circuit's `Streams<F>` exactly)

- Host hands the interpreter one or more byte streams via
  `IoState::with_input` (single) or `with_input_streams` (many — one entry
  per `StdIn::write_bytes` call).
- The guest's `openvm::io::read()` runs `Reader::new()` which:
  1. Fires the `HintInput` phantom (`0x0b`/funct3=0b011/imm=0).
     The interpreter pops the next input stream, prepends its u32 LE length,
     pads to 4-byte boundary, and dumps the result into `hint_stream`.
  2. Pulls 4 bytes via HINT_STOREW to learn the byte count.
  3. Pulls the rest via HINT_BUFFER.
- REVEAL (`0x0b`/funct3=0b010) writes `rs1` (a u32) at offset `[rd]+imm` of
  the public-output buffer. `reveal_bytes32` calls this 8 times.
- HintNonQr / HintSqrt **append** to `hint_stream` without clearing — the
  guest reads them next via HINT_STOREW / HINT_BUFFER.

## Quickstart

```bash
cd /workspace/sim
cargo build --release
cargo test           # 11 tests pass (RV32IM core + INT256 + Keccak-f vector)
```

### Run a tiny test fixture

```bash
cd tests/fixtures/echo-guest && cargo +nightly-2026-01-18 build --release
cd /workspace/sim
printf '\xde\xad\xbe\xef\x12\x34\x56\x78\xab\xcd\xef\x01\xff\xee\xdd\xcc' > /tmp/echo.bin
target/release/openvm-sim run \
    --elf tests/fixtures/echo-guest/target/riscv32im-unknown-none-elf/release/echo-guest \
    --input /tmp/echo.bin --hex
# Output: deadbeef12345678abcdef01ffeeddcc
```

### Run the real Reth stateless-guest

```bash
# (1) Build the input-prep tool — only needed once. This is the only place
# we touch openvm; the interpreter itself stays clean.
cd /workspace/sim/tools/input-prep
cargo build --release

# (2) Convert the cached witness produced by openvm-reth-benchmark.
./target/release/openvm-sim-input-prep \
    --cache /workspace/rpc-cache/input/1/23992138.bin \
    --out /tmp/reth_input.bin

# (3) Run the guest.
cd /workspace/sim
target/release/openvm-sim run \
    --elf /workspace/bin/reth-benchmark/elf/openvm-stateless-guest \
    --input /tmp/reth_input.bin --max-steps 1_000_000_000_000 --hex
```

Current state for block 23992138 — the interpreter executes the **entire
block end-to-end** and produces the **canonical block hash**:

```
output:    b0c6920a15b5f11db176fcd1b22754fe845f9f5b24a245f1c67b997f353f3878
canonical: 0xb0c6920a15b5f11db176fcd1b22754fe845f9f5b24a245f1c67b997f353f3878
```

The interpreter:
- Deserialises the input (`StatelessExecutorInput`).
- Runs MPT pre-state validation (Keccak heavy).
- Recovers signers for all 240 transactions (secp256k1 modular arithmetic
  + HintSqrt for point decompression).
- Executes all 240 transactions (~1.01 B RISC-V instructions).
- Handles three BN254 pairing calls *and* at least one BLS12-381 pairing
  call from contract code, all accepted by the in-circuit residue-witness
  check.
- Validates the post-execution state root and reveals the block hash.

## Other gaps worth noting

- **SHA-512**: handler returns an "unknown funct7" error if the guest ever
  emits one. Reth's stateless guest does not — but if you swap in a guest
  that does, add `do_sha512_compress` mirroring `do_sha256_compress`.

## Subtleties that took experimentation to find

Implementing this interpreter and matching the canonical block hash
exactly turned up several non-obvious differences from the upstream
`openvm-org/openvm` ABI:

1. **Keccak primitive, not full hash.** The powdr fork at
   `v2-powdr-beta.2` exposes `KECCAKF` (one Keccak-f[1600] permutation on
   a 200-byte state) + `XORIN` (XOR bytes into the state). The full
   `keccak256(bytes, len)` lives in `openvm-keccak256-guest`'s wrapper.
2. **SHA-256 compression, with LE u32 state.** `funct7=2` is one
   SHA-256 compression block. openvm-circuit reads the 32-byte state via
   `state.as_mut_ptr() as *mut [u32; 8]`, i.e. *native-endian* — which is
   little-endian on RISC-V. Treating the state as big-endian (the FIPS-180
   convention) leads to a working keccak but an MPT mismatch much later.
3. **`IsEqMod` writes the result to `rd` directly**, not to memory at
   `[rd]`. The address space for the destination is the **register file**
   for IsEq (`vm_write(RV32_REGISTER_AS, ...)`), unlike Add/Sub/Mul/Div
   which target memory.
4. **`HintNonQr` / `HintSqrt` *replace* `hint_stream`** (clear + extend),
   not append.
5. **`find_non_qr` must match openvm exactly**, including its fast paths
   for `p ≡ 3 (mod 4)` (returns `p − 1`) and `p ≡ 5 (mod 8)` (returns 2),
   and its deterministic `StdRng::from_seed([0u8; 32])` rejection
   sampling for the remaining moduli. The guest consumer's choice of
   `NON_QR` is whatever the host fed it at runtime, so the host and
   interpreter must agree.
6. **`HintInput` phantom prepends a u32 LE length** before the entry
   bytes when populating `hint_stream`, and pads the entry to a 4-byte
   boundary. This is what `openvm::io::Reader::new()` immediately reads
   via `read_u32()` to learn the size.
7. **Pairing `HintFinalExp` for BN254 and BLS12-381** uses the
   residue-witness algorithm from Gnark / eprint 2024/640. Output is
   `(c, u)` (BN254) or `(c, s)` (BLS12-381), both 12·Fq elements each,
   pushed into the hint stream in the Fq12 flattening order
   `[c0.c0, c1.c0, c0.c1, c1.c1, c0.c2, c1.c2]`.

Verification helper:

```bash
# Get canonical per-tx cumulative gas and block hash from the host-mode
# StatelessExecutor (uses the same cached witness, no RPC):
cd sim/tools/canonical-gas
cargo run --release -- --cache /workspace/rpc-cache/input/1/23992138.bin

# Run the interpreter and compare:
cd /workspace/sim
./target/release/openvm-sim run \
    --elf /workspace/bin/reth-benchmark/elf/openvm-stateless-guest \
    --input /tmp/reth_input.bin --max-steps 10000000000000 --hex
```

## Architecture

### `crates/elf` — ELF loader
```rust
pub fn load_rv32_elf(bytes: &[u8]) -> Result<LoadedProgram, ElfError>;
```
Reads program headers, copies LOAD segments into the simulator's address
space. Validates `EM_RISCV`, `ELFCLASS32`, little-endian.

### `crates/rv32im` — CPU core
```rust
pub struct Cpu { pub pc: u32, pub x: [u32; 32], pub mem: Memory, pub steps: u64 }
pub trait CustomOpHandler {
    fn handle(&mut self, cpu: &mut Cpu, insn: u32) -> Result<StepOutcome, CpuError>;
}
```
- Sparse paged memory (4 KiB pages).
- Full RV32IM: I/U, R, R-M, branch, jump, load/store, FENCE.
- Custom opcodes 0x0b/0x2b are delegated to a `CustomOpHandler`. The
  handler is also responsible for advancing `cpu.pc` (the executor only
  auto-advances if the handler left it unchanged — that lets branch-style
  custom ops like BEQ256 set their own target).
- Stack top defaults to `0xFFFF_FFF0`.

### `crates/precompiles` — Custom-opcode dispatcher

Implements `CustomOpHandler` and dispatches on `(opcode, funct3, funct7)`.
All precompiles pure-Rust. Modular arithmetic over `num-bigint` for the 8
runtime-known moduli; Short-Weierstrass ECC for 4 curves built on `BigUint`.
Tonelli–Shanks for modular square root (used by HintSqrt and ECC
HintDecompress).

`PrecompileHandler::io: IoState` mirrors openvm-circuit's `Streams<F>`:
`input_streams` (FIFO of stream entries), `hint_stream` (active byte
deque), `output` (public-output buffer for REVEAL).

### `crates/runner` — CLI

```
openvm-sim run --elf <ELF> [--input <PATH>] [--max-steps N] [--hex]
openvm-sim info --elf <ELF>
```

## Adding a new precompile

The dispatcher in `crates/precompiles/src/lib.rs` is a flat `match` on
`funct3` per custom opcode slot. Look up the funct3/funct7 in
`src/encoding.rs`, add a module that exposes one or more `handle_xxx`
functions which read operands from `cpu` and either write back or push to
`io.hint_stream`, then wire it into `handle_custom0` / `handle_custom1`.

## Out of scope

- Autoprecompiles (APC), ZK proving, GPU paths.
- Continuations / segmentation — single TERMINATE ends execution.
