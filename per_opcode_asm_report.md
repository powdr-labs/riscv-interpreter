# Per-opcode RV32IM asm experiment

Block 23992138 (mainnet), baseline RV32IM steps: **1,011,316,413**, canonical
block hash `0xb0c6920a15b5f11db176fcd1b22754fe845f9f5b24a245f1c67b997f353f3878`.

After AOT/BB transpilation experiments hit a dispatch-tax floor at +2.58%
(see `aot-experiments-checkpoint` branch report), we pivoted: keep revm's
per-opcode dispatch intact and instead transpile individual opcode bodies to
inline RV32IM `asm!` where Rust → LLVM → RV32IM compiles poorly.

## Approach

Two surgical primitives added to `StackTr`:

- `top_pair_ptr_unchecked(&mut self) -> (*mut U256, *mut U256)` — pointers
  to second-from-top and top, for in-place writes
- `top_ptr_unchecked(&mut self) -> *mut U256` — pointer to top
- `shrink_unchecked(&mut self, n: usize)` — set_len(len - n)
- `discard_top(&mut self) -> bool` — pop without reading the value
- `push_uninit_unchecked(&mut self) -> *mut U256` — increment len + return
  pointer to the new (uninitialised) top slot

Plus a per-opcode `#[cfg(target_os = "zkvm")]` asm path operating directly
on stack memory. Host path stays as the original Rust.

We added a one-shot opcode profiler partway through (see "Recommended next
moves" below for why this should have come first).

## Final results

| variant | steps | Δ baseline |
|---|---|---|
| baseline (vanilla revm 32.0.0) | 1,011,316,413 | — |
| + DUP/SWAP/POP asm | 974,035,773 | −3.69% |
| + ADD/SUB/AND/OR/XOR/NOT/ISZERO/EQ asm | 956,490,607 | −5.42% |
| + LT/GT/SLT/SGT asm | 956,226,927 | −5.45% |
| + MLOAD asm | 955,573,346 | −5.51% |
| + PUSH1..PUSH32 asm | 954,635,458 | −5.61% |
| + CALLDATALOAD asm | 954,480,579 | **−5.62%** |

**Cumulative: −56,835,834 RV32IM steps = −5.62%. Canonical block hash unchanged.**

## What worked

Opcodes with simple per-call work benefited from bypassing `popn_top!`'s
32-byte value copy:

- **DUP/SWAP/POP** (the user's hypothesis): biggest single win at −3.69%.
  `Stack::dup`/`Stack::exchange` used `ptr::copy_nonoverlapping(_, _, 1)` for
  `U256` (32 bytes), which LLVM lowered to a memcpy-style loop. Hand-rolled
  16 lw+sw for DUP, 32 for SWAP. POP's `popn!([_i], ...)` did a 32-byte
  read-then-drop; new `discard_top()` skips the read entirely.
- **ADD/SUB/AND/OR/XOR/NOT/ISZERO/EQ** (−1.73% incremental): 8-limb chains
  hand-rolled in asm, operating in place via `top_pair_ptr_unchecked()`.
- **LT/GT/SLT/SGT** (−0.03% incremental): 8-limb sub-borrow chain. Signed
  variants flip the MSB limb with sign mask. Smaller than expected because
  ruint's compare has early-out for non-equal high limbs.
- **MLOAD** (−0.07% incremental): byteswap-write directly to stack U256.
- **PUSH1..PUSH32** (−0.10% incremental): zero 32 bytes, then byte-reversed
  copy of N bytes. Smaller than estimated because `push_slice_`'s
  u64-from-be path was already tight under LTO for small N.
- **CALLDATALOAD** (−0.015% incremental): fast-path for the common case
  (offset + 32 ≤ input.len(), `CallInput::Bytes`) using the same byteswap
  asm shape as MLOAD. Falls through to original Rust on partial/SharedBuffer.

## What didn't pay off (reverted)

| attempted | regression | reason |
|---|---|---|
| MSTORE asm via new `raw_mut_ptr` trait method | +2.35M cycles | trait dispatch + RefCell borrow setup outweighed byteswap savings vs `value.to_be_bytes::<32>()` + `memory.set` |
| BYTE asm | +509K (combined) | bounds-check branches + manual masking matched Rust's `as_usize_saturated + op2.byte(31-o1) + U256::from(u8)` |
| SHL/SHR/SAR with popn_top bypass + Rust shift | (combined) | the actual multi-limb shift dominates; ruint shift is already tight under LTO |
| SIGNEXTEND with bypass | (combined) | mask + bit-test logic dominates |
| EXP with bypass | (combined) | gas calc + pow inner ops dominate |
| ADDMOD/MULMOD with `top_triple_ptr_unchecked` bypass | (combined) | 256-bit mod arithmetic dominates per-call cost |

## The pattern

The bypass + asm wins when:
1. The opcode pops 1-2 values that are 32 bytes each, AND
2. The inner operation is small (8-32 ops) — comparable to or smaller than
   the 32-byte popn copy.

The bypass loses when the inner Rust operation is large (multi-precision
shift/mul/div/mod, gas calc, mod arithmetic). The bypass overhead is 5-15
ops, wasted when the body is already 100+ ops.

**Bypass shaves overhead off small opcodes; for big opcodes the body
dominates.**

## Per-opcode invocation profile

Captured during a one-shot run with instrumentation in `step()`. Top
opcodes by invocation count for block 23992138:

| opcode | hex | count | status |
|---|---|---|---|
| PUSH1 | 0x60 | 428,867 | asm |
| PUSH2 | 0x61 | 403,115 | asm |
| JUMPDEST | 0x5b | 258,352 | (no-op already) |
| POP | 0x50 | 206,875 | asm |
| JUMPI | 0x57 | 202,845 | — |
| SWAP1 | 0x90 | 189,219 | asm |
| DUP2 | 0x81 | 179,155 | asm |
| ADD | 0x01 | 170,904 | asm |
| DUP1 | 0x80 | 150,101 | asm |
| JUMP | 0x56 | 146,027 | — |
| DUP3 | 0x82 | 123,005 | asm |
| MSTORE | 0x52 | 105,795 | reverted |
| MLOAD | 0x51 | 104,520 | asm |
| ISZERO | 0x15 | 103,640 | asm |
| SWAP2 | 0x91 | 95,591 | asm |
| AND | 0x16 | 95,094 | asm |
| DUP4 | 0x83 | 73,580 | asm |
| EQ | 0x14 | 61,360 | asm |
| SUB | 0x03 | 60,906 | asm |
| PUSH4 | 0x63 | 52,783 | asm |
| LT | 0x10 | 43,489 | asm |
| SHL | 0x1b | 38,638 | reverted |
| SHR | 0x1c | 35,109 | reverted |
| GT | 0x11 | 34,955 | asm |
| CALLDATALOAD | 0x35 | 31,625 | asm |
| MUL | 0x02 | 24,061 | — |
| PUSH20 | 0x73 | 22,765 | asm |
| PUSH32 | 0x7f | 21,874 | asm |
| DIV | 0x04 | 19,674 | — |
| OR | 0x17 | 17,295 | asm |
| SLOAD | 0x54 | 13,857 | — |

Diminishing returns: hot opcodes left untouched are JUMPDEST (no body),
JUMPI/JUMP (efficient already), MUL/DIV (hard), SLOAD (host-bound), and a
long tail of <15K calls each.

## What's still untouched, ranked by realistic upside

### Tier 1 — worth trying (estimated 1-5M cycles each)

1. **MSTORE redo with closure-based trait method.** The prior raw_mut_ptr
   approach paid a RefMut setup that dominated savings. A closure API
   (`fn write_at<F>(&mut self, offset, len, F)` where the closure receives
   `*mut u8` inside the borrow scope) would avoid the borrow drop/raw-ptr
   handoff. 106K MSTOREs × ~10 ops potential = ~1M cycles.

2. **MSTORE8.** Single byte store. Currently uses `value.byte(0)` +
   `memory.set(offset, &[byte])`. Asm: 1 sb. Frequency unknown — was in the
   long tail; check the profile.

3. **CALLDATACOPY / CODECOPY / RETURNDATACOPY.** Bulk memcpy from one
   buffer to another. Current Rust uses `set_data` which may go through
   slow paths. Asm-level memcpy in 4-byte chunks would tighten these.

4. **MCOPY (Cancun).** Memory-to-memory copy. Same shape as the *COPY family.

5. **OR asm.** 17K calls and we already wrote AND/XOR. Five-minute add.

6. **CALLDATASIZE / MSIZE / RETURNDATASIZE.** Push a usize-derived U256.
   Currently `push!(...U256::from(size))`. Asm: 1 sw of size to limb[0],
   7 sw zero. Push count check stays. Probably ~3-5 ops saved per call.
   Counts: CALLDATASIZE shows 14,598 (opcode 0x36 from histogram).

### Tier 2 — bigger lift, uncertain payoff (5-30M cycles ceiling)

7. **`ruint::Uint<256, 8>` u32 limbs instead of `Uint<256, 4>` u64 limbs.**
   On RV32IM without u64 hardware, each u64 op decomposes to 2-4 u32 ops
   with carry plumbing LLVM doesn't always tighten. Forking ruint to use
   8 u32 limbs would map 1:1 to RV32 instructions. Speculative — could be
   0 or could be 5%+.

8. **Static gas pre-debit per basic block.** revm's `step()` does
   `record_cost_unsafe(static_gas)` per opcode (~5 ops). Block-aware
   pre-debit would batch this — but requires basic-block analysis, which
   was the dispatch-tax problem in the AOT branch. Could shave the
   per-step gas cost from ~5 to ~1.

9. **Eliminate trait dispatch in `step`.** `instruction_table.get_unchecked(opcode)`
   then virtual call to the handler. With 256 opcodes and per-opcode body
   being small, the function-call ABI cost is non-trivial. A monolithic
   `match opcode { ... }` in step() would let LLVM inline more aggressively.
   Big refactor.

10. **MUL asm with 8-limb schoolbook.** 24K calls. Ruint's wrapping_mul
    probably already does 4×4 u64 = 16 mulu64 = 64 u32 muls + carries.
    Asm version same ops. Likely no win unless we have a custom trick.

### Tier 3 — speculative / high-effort

11. **Add a new openvm RV32IM-extension circuit for 256-bit ops.** e.g.,
    a single instruction for 256-bit add. Would require modifying openvm's
    chip set, the sim, and the guest's compiler intrinsics. The user
    explicitly rejected this route earlier (the INT256_ADD precompile
    experience), but it's the asymptotic ceiling.

12. **Tail-call threading in `step`.** Replace the dispatch loop with each
    handler ending in `become next_handler()` — eliminates the loop and
    return-to-loop overhead. Requires nightly Rust feature.

13. **Hot-bytecode AOT cache.** Compile frequently-executed bytecode regions
    to native RV32 at runtime, cache by code_hash. This was the AOT branch
    direction and we found dispatch-tax floors. Lessons learned may enable
    a second attempt with the current asm primitives.

14. **JIT replace common patterns.** e.g., the EVM selector-dispatch shape
    (DUP1 PUSH4 EQ PUSH2 JUMPI) — we showed −1.20% from a single shape
    fast-path. There may be ~5-10 common shapes worth shape-matching.

## Recommended next moves

In order:

1. Apply the cheap Tier 1 wins (MSTORE redo, MSTORE8, OR, CALLDATASIZE,
   *COPY family). Estimated combined upside 3-8M cycles ≈ 0.3-0.8%.
2. Profile *inside* the still-untouched hot opcodes (JUMP, JUMPI, SLOAD,
   MUL, DIV) to see whether the cost is body or host. This wasn't done
   yet — we only counted invocations.
3. After Tier 1, decide on Tier 2 based on whether the data justifies the
   refactor (ruint switch, dispatch flattening). These are weeks of effort
   each.

## One small lesson

I should have added the opcode profiler *before* the SHL/SHR/EXP/ADDMOD/MULMOD
asm attempt. The profile showed those would have been ~0.01% wins each
under perfect asm, which is below the noise floor of the bypass overhead I
was introducing. Profiling first would have ranked PUSH and MSTORE above
the shifts, and we'd have skipped the regression-then-revert dance.

The 5.62% is real and the canonical block hash is preserved end-to-end
through all 240 transactions.
