//! Re-runs the openvm-stateless-executor on the cached witness using the
//! exact same code path the parent workspace uses for `--mode execute-host`
//! — but stops after `block_executor.execute()` so we can print
//! per-transaction `cumulative_gas_used`. This gives us the canonical gas
//! breakdown to diff against our RV32 interpreter's `gas_spent_by_tx`.

use anyhow::{Context, Result};
use clap::Parser;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use alloy_consensus::TxReceipt;
use openvm_chainspec::mainnet;
use openvm_stateless_executor::io::{StatelessExecutorInput, StatelessExecutorInputWithState};
use reth_evm::execute::{BasicBlockExecutor, Executor};
use reth_evm_ethereum::EthEvmConfig;
use reth_primitives_traits::block::Block as _;
use reth_revm::db::CacheDB;

#[derive(Parser, Debug)]
struct Cli {
    /// Bincode cache produced by openvm-reth-benchmark (rpc-cache/input/<chain>/<block>.bin).
    #[arg(long)]
    cache: PathBuf,
    /// Print full Debug of this tx index to stderr.
    #[arg(long)]
    detail: Option<usize>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let bytes = fs::read(&cli.cache)
        .with_context(|| format!("reading {}", cli.cache.display()))?;
    let (pre_input, _): (StatelessExecutorInput, usize) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard())?;

    let mut input = StatelessExecutorInputWithState::build(pre_input)
        .map_err(|e| anyhow::anyhow!("input build: {e:?}"))?;

    let witness_db = input.witness_db().map_err(|e| anyhow::anyhow!("witness_db: {e:?}"))?;
    let cache_db = CacheDB::new(&witness_db);

    let spec = Arc::new(mainnet());
    let current_block = input
        .input
        .current_block
        .clone()
        .try_into_recovered()
        .map_err(|e| anyhow::anyhow!("recover senders: {e:?}"))?;

    let block_executor = BasicBlockExecutor::new(EthEvmConfig::new(spec.clone()), cache_db);
    let executor_output = block_executor
        .execute(&current_block)
        .map_err(|e| anyhow::anyhow!("execute: {e:?}"))?;

    println!("# canonical per-tx cumulative gas (block {})",
        input.input.current_block.header.number);

    for (i, r) in executor_output.receipts.iter().enumerate() {
        println!("({}, {})", i, r.cumulative_gas_used());
    }
    println!("# block hash: 0x{:x}", input.input.current_block.header.hash_slow());
    if let Some(idx) = cli.detail {
        let txs = &input.input.current_block.body.transactions;
        if let Some(tx) = txs.get(idx) {
            eprintln!("--- detail tx {} ---", idx);
            eprintln!("{:#?}", tx);
        }
    }
    Ok(())
}
