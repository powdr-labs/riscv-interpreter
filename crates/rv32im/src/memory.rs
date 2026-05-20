//! Sparse paged 32-bit memory.
//!
//! The OpenVM guest ELF lays segments at virtual addresses up to about
//! 0x0060_0000, the stack lives near the top of the 32-bit space, and the
//! heap grows somewhere in between. A flat 4 GiB allocation is wasteful;
//! a hash-mapped 4 KiB-page model keeps RSS proportional to what the guest
//! actually touches.

use std::collections::HashMap;

const PAGE_BITS: u32 = 12;
pub const PAGE_SIZE: usize = 1 << PAGE_BITS; // 4096
const PAGE_MASK: u32 = (PAGE_SIZE as u32) - 1;

#[derive(Debug, Default)]
pub struct Memory {
    pages: HashMap<u32, Box<[u8; PAGE_SIZE]>>,
}

impl Memory {
    pub fn new() -> Self {
        Self::default()
    }

    fn page_idx(addr: u32) -> u32 {
        addr >> PAGE_BITS
    }
    fn page_off(addr: u32) -> usize {
        (addr & PAGE_MASK) as usize
    }

    fn page_mut(&mut self, idx: u32) -> &mut [u8; PAGE_SIZE] {
        self.pages
            .entry(idx)
            .or_insert_with(|| Box::new([0u8; PAGE_SIZE]))
    }

    /// Read a single byte (zero outside touched pages).
    pub fn read_u8(&self, addr: u32) -> u8 {
        self.pages
            .get(&Self::page_idx(addr))
            .map(|p| p[Self::page_off(addr)])
            .unwrap_or(0)
    }

    pub fn write_u8(&mut self, addr: u32, val: u8) {
        let idx = Self::page_idx(addr);
        self.page_mut(idx)[Self::page_off(addr)] = val;
    }

    /// Reads cross page boundaries naturally because the byte API is per-address.
    pub fn read_u16(&self, addr: u32) -> u16 {
        let lo = self.read_u8(addr) as u16;
        let hi = self.read_u8(addr.wrapping_add(1)) as u16;
        lo | (hi << 8)
    }

    pub fn read_u32(&self, addr: u32) -> u32 {
        // Fast path: aligned, single page.
        if addr & 3 == 0 {
            if let Some(p) = self.pages.get(&Self::page_idx(addr)) {
                let o = Self::page_off(addr);
                return u32::from_le_bytes([p[o], p[o + 1], p[o + 2], p[o + 3]]);
            }
            return 0;
        }
        let b0 = self.read_u8(addr) as u32;
        let b1 = self.read_u8(addr.wrapping_add(1)) as u32;
        let b2 = self.read_u8(addr.wrapping_add(2)) as u32;
        let b3 = self.read_u8(addr.wrapping_add(3)) as u32;
        b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    }

    pub fn write_u16(&mut self, addr: u32, val: u16) {
        self.write_u8(addr, val as u8);
        self.write_u8(addr.wrapping_add(1), (val >> 8) as u8);
    }

    pub fn write_u32(&mut self, addr: u32, val: u32) {
        if addr & 3 == 0 {
            let idx = Self::page_idx(addr);
            let o = Self::page_off(addr);
            let p = self.page_mut(idx);
            let bs = val.to_le_bytes();
            p[o] = bs[0];
            p[o + 1] = bs[1];
            p[o + 2] = bs[2];
            p[o + 3] = bs[3];
            return;
        }
        let bs = val.to_le_bytes();
        for (i, b) in bs.iter().enumerate() {
            self.write_u8(addr.wrapping_add(i as u32), *b);
        }
    }

    /// Copy `data` into memory starting at `addr`. Used by the ELF loader.
    pub fn write_slice(&mut self, addr: u32, data: &[u8]) {
        for (i, b) in data.iter().enumerate() {
            self.write_u8(addr.wrapping_add(i as u32), *b);
        }
    }

    /// Reads `len` bytes into a Vec (used by precompiles).
    pub fn read_vec(&self, addr: u32, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| self.read_u8(addr.wrapping_add(i as u32)))
            .collect()
    }
}
