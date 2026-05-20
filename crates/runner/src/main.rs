//! Decoupled RISC-V interpreter for OpenVM guest ELFs.
//!
//! Usage:
//!   openvm-sim run --elf <ELF> [--input <PATH>] [--max-steps N]
//!   openvm-sim info --elf <ELF>

use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sim_elf::load_rv32_elf;
use sim_precompiles::PrecompileHandler;
use sim_rv32im::Cpu;

#[derive(Parser, Debug)]
#[command(name = "openvm-sim", version, about = "Decoupled RV32IM interpreter that mirrors OpenVM execution semantics")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Execute the guest ELF and print the public output.
    Run {
        /// Path to the OpenVM-compiled guest ELF (riscv32im EXEC).
        #[arg(long)]
        elf: PathBuf,

        /// Path to raw input bytes (the same bytes the host SDK would feed
        /// the guest's hint stream). Use "-" or omit for empty.
        #[arg(long)]
        input: Option<PathBuf>,

        /// Maximum number of instructions to execute.
        #[arg(long, default_value_t = 10_000_000_000u64)]
        max_steps: u64,

        /// Print the public output as plain hex (no `0x`).
        #[arg(long)]
        hex: bool,
    },
    /// Print a summary of the ELF (entry point + segments).
    Info {
        #[arg(long)]
        elf: PathBuf,
    },
}

fn read_input(path: Option<&PathBuf>) -> Result<Vec<u8>> {
    match path {
        None => Ok(Vec::new()),
        Some(p) if p.as_os_str() == "-" => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            Ok(buf)
        }
        Some(p) => Ok(fs::read(p).with_context(|| format!("reading input {}", p.display()))?),
    }
}

fn cmd_run(elf: &PathBuf, input: Option<&PathBuf>, max_steps: u64, as_hex: bool) -> Result<()> {
    let bytes = fs::read(elf).with_context(|| format!("reading ELF {}", elf.display()))?;
    let prog = load_rv32_elf(&bytes)?;
    tracing::info!(
        entry = format!("0x{:08x}", prog.entry),
        segments = prog.segments.len(),
        high = format!("0x{:08x}", prog.memory_high_water()),
        "loaded ELF"
    );

    let input_bytes = read_input(input)?;
    tracing::info!(input_len = input_bytes.len(), "supplying input bytes");

    let mut cpu = Cpu::new(&prog);
    let mut handler = PrecompileHandler::new(input_bytes);

    let exit = cpu.run(&mut handler, max_steps)?;
    tracing::info!(
        steps = cpu.steps,
        exit_code = exit,
        output_len = handler.io.output.len(),
        "program terminated"
    );

    let out = &handler.io.output;
    if as_hex {
        for b in out {
            print!("{:02x}", b);
        }
        println!();
    } else {
        // Hex with 0x prefix and split into 32-byte chunks for readability.
        for (i, chunk) in out.chunks(32).enumerate() {
            print!("[{:>2}] 0x", i);
            for b in chunk {
                print!("{:02x}", b);
            }
            println!();
        }
    }
    Ok(())
}

fn cmd_info(elf: &PathBuf) -> Result<()> {
    let bytes = fs::read(elf).with_context(|| format!("reading ELF {}", elf.display()))?;
    let prog = load_rv32_elf(&bytes)?;
    println!("entry: 0x{:08x}", prog.entry);
    println!("high water: 0x{:08x}", prog.memory_high_water());
    println!("segments ({}):", prog.segments.len());
    for s in &prog.segments {
        println!(
            "  vaddr=0x{:08x} mem_size=0x{:x} file_size=0x{:x} flags={}{}{}",
            s.vaddr,
            s.mem_size,
            s.data.len(),
            if true { "R" } else { "-" },
            if s.writable { "W" } else { "-" },
            if s.executable { "X" } else { "-" },
        );
    }
    Ok(())
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Command::Run { elf, input, max_steps, hex } => cmd_run(&elf, input.as_ref(), max_steps, hex),
        Command::Info { elf } => cmd_info(&elf),
    }
}
