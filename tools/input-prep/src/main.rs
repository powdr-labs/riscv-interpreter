//! Convert the bincode-cached `StatelessExecutorInput` (produced by
//! `openvm-reth-benchmark` while populating `rpc-cache/`) into the byte
//! stream the OpenVM guest consumes from its hint inputs.
//!
//! The stream format mirrors what the SDK does at runtime:
//!   1. `openvm::serde::to_vec(&input)` → Vec<u32>
//!   2. Flatten each u32 to 4 little-endian bytes
//!
//! Those bytes are then read by the guest 4 at a time via `HINT_STOREW` and
//! `HINT_BUFFER`. We don't add any envelope prefix — the runtime's "0x01"
//! tag visible in `--mode make-input` JSON is purely a host-side stream
//! marker the SDK strips before piping to the guest.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use openvm_stateless_executor::io::StatelessExecutorInput;

#[derive(Parser, Debug)]
#[command(name = "openvm-sim-input-prep", about = "Convert cached witness bincode → openvm-serde stream bytes")]
struct Cli {
    /// Path to the bincode-cached `StatelessExecutorInput`.
    /// Typically `rpc-cache/input/<chain_id>/<block_number>.bin`.
    #[arg(long)]
    cache: PathBuf,

    /// Output path. Use `-` for stdout.
    #[arg(long, default_value = "-")]
    out: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let bytes = fs::read(&cli.cache)
        .with_context(|| format!("reading cache {}", cli.cache.display()))?;
    let (input, _): (StatelessExecutorInput, usize) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
            .context("bincode decode StatelessExecutorInput")?;

    let words: Vec<u32> = openvm::serde::to_vec(&input).context("openvm::serde::to_vec")?;
    let out_bytes: Vec<u8> = words.into_iter().flat_map(|w| w.to_le_bytes()).collect();
    eprintln!(
        "openvm-sim-input-prep: produced {} bytes ({} u32 words)",
        out_bytes.len(),
        out_bytes.len() / 4
    );

    if cli.out.as_os_str() == "-" {
        std::io::stdout().write_all(&out_bytes)?;
    } else {
        fs::write(&cli.out, &out_bytes)
            .with_context(|| format!("writing {}", cli.out.display()))?;
    }
    Ok(())
}
