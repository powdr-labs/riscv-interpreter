//! Minimal ELF32-LE RISC-V loader for the simulator.
//!
//! We only need the program headers — each `LOAD` segment is copied verbatim
//! into the simulator's address space at the segment's virtual address. The
//! ELF we feed in is a fully-linked EXEC, so relocations are informational
//! and intentionally ignored.

use elf::{abi, endian::LittleEndian, ElfBytes};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ElfError {
    #[error("elf parse: {0}")]
    Parse(#[from] elf::ParseError),
    #[error("expected ELFCLASS32, got class {0}")]
    NotElf32(u8),
    #[error("expected little-endian, got endianness {0}")]
    NotLittleEndian(u8),
    #[error("expected EM_RISCV (243), got machine {0}")]
    NotRiscv(u16),
    #[error("expected ET_EXEC, got type {0}")]
    NotExec(u16),
    #[error("no program headers")]
    NoProgramHeaders,
    #[error("segment size mismatch: file=0x{file_sz:x} > mem=0x{mem_sz:x}")]
    SegmentSizeMismatch { file_sz: u64, mem_sz: u64 },
}

/// One loadable segment ready to be copied into simulator memory.
#[derive(Debug, Clone)]
pub struct Segment {
    pub vaddr: u32,
    pub mem_size: u32,
    pub writable: bool,
    pub executable: bool,
    /// File data; if shorter than `mem_size` the remainder is zero-filled (BSS).
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct LoadedProgram {
    pub entry: u32,
    pub segments: Vec<Segment>,
}

impl LoadedProgram {
    /// Highest `(vaddr + mem_size)` across all segments.
    pub fn memory_high_water(&self) -> u32 {
        self.segments
            .iter()
            .map(|s| s.vaddr.saturating_add(s.mem_size))
            .max()
            .unwrap_or(0)
    }
}

pub fn load_rv32_elf(bytes: &[u8]) -> Result<LoadedProgram, ElfError> {
    // Pre-flight ident-byte checks for clearer error messages.
    if bytes.len() >= 6 {
        if bytes[4] != abi::ELFCLASS32 {
            return Err(ElfError::NotElf32(bytes[4]));
        }
        if bytes[5] != abi::ELFDATA2LSB {
            return Err(ElfError::NotLittleEndian(bytes[5]));
        }
    }

    let file = ElfBytes::<LittleEndian>::minimal_parse(bytes)?;

    if file.ehdr.e_machine != abi::EM_RISCV {
        return Err(ElfError::NotRiscv(file.ehdr.e_machine));
    }
    if file.ehdr.e_type != abi::ET_EXEC {
        return Err(ElfError::NotExec(file.ehdr.e_type));
    }

    let phdrs = file.segments().ok_or(ElfError::NoProgramHeaders)?;
    let mut segments = Vec::new();

    for ph in phdrs.iter() {
        if ph.p_type != abi::PT_LOAD {
            continue;
        }
        if ph.p_filesz > ph.p_memsz {
            return Err(ElfError::SegmentSizeMismatch {
                file_sz: ph.p_filesz,
                mem_sz: ph.p_memsz,
            });
        }
        let off = ph.p_offset as usize;
        let fsz = ph.p_filesz as usize;
        let data = bytes[off..off + fsz].to_vec();

        segments.push(Segment {
            vaddr: ph.p_vaddr as u32,
            mem_size: ph.p_memsz as u32,
            writable: (ph.p_flags & abi::PF_W) != 0,
            executable: (ph.p_flags & abi::PF_X) != 0,
            data,
        });
    }

    Ok(LoadedProgram {
        entry: file.ehdr.e_entry as u32,
        segments,
    })
}
