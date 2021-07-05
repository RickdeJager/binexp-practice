use std::path::Path;
use std::convert::TryFrom;

use crate::{Section};
use crate::mmu::{Mmu, Perm, VirtAddr};
use crate::mmu::{PERM_WRITE, PERM_READ, PERM_RAW, PERM_EXEC};

// TODO; Move these macro's into MMU
/// Small little helper macro to get type lengths at compile time
macro_rules! get_type_len {
    (u8)   => {1};
    (u16)  => {2};
    (u32)  => {4};
    (u64)  => {8};
    (u128) => {16};
    (i8)   => {1};
    (i16)  => {2};
    (i32)  => {4};
    (i64)  => {8};
    (i128) => {16};
}

/// Macro to read a value from memory while honouring the perms
macro_rules! mmu_read_perms {
    ($mmu: expr, $addr: expr, $perms: expr, $type: tt) => {
        {
            let mut tmp = [0u8; get_type_len!($type)];
            $mmu.read_into_perms($addr, &mut tmp, $perms)?;
            Some(<$type>::from_ne_bytes(tmp))
        }
    };
}

/// Macro to read a value from memory with PERM_READ
macro_rules! mmu_read {
    ($mmu: expr, $addr: expr, $type: tt) => {
        {
            let mut tmp = [0u8; get_type_len!($type)];
            $mmu.read_into_perms($addr, &mut tmp, Perm(PERM_READ))?;
            Some(<$type>::from_ne_bytes(tmp))
        }
    };
}

/// Macro to write a value to memory
macro_rules! mmu_write {
    ($mmu: expr, $addr: expr, $value: expr) => {
        {
            let tmp = $value::to_ne_bytes(tmp) 
            $mmu.write_from($addr, &tmp)?;
            Some(())
        }
    };
}


pub struct Emulator {
    /// The memory belonging to this emu
    pub memory: Mmu,

    /// Register state
    registers: [u64; 33]
}


/// 64 bit RISC-V registers
/// See: Chapter 25; RISC-V Assembly Programmer’s Handbook
#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub enum Register {
    Zero = 0,   // Zero
    Ra,         // Return addr
    Sp,         // Stack Pointer
    Gp,         // Global Pointer
    Tp,         // Thread Pointer
    T0,         // Temp / alt. link register
    T1,         // Temp
    T2,
    S0,         // Saved register / frame pointer
    S1,         // Saved register
    A0,         // Function args / return values
    A1,
    A2,         // Functions args
    A3,
    A4,
    A5,
    A6,
    A7,
    S2,         // Saved registers
    S3,
    S4,
    S5,
    S6,
    S7,
    S8,
    S9,
    S10,
    S11,
    T3,         // Temp
    T4,
    T5,
    T6,
    Pc,         // Program counter
}

impl Emulator {
    /// Create a new emulator with `size` bytes of memory
    pub fn new(size: usize) -> Self {
        Emulator {
            memory: Mmu::new(size),
            registers: [0u64; 33],
        }
    }

    /// Reset the state of self to the state of another emu.
    /// REQUIRES that `self` is a fork of `other`, because we will only be restoring dirtied pages.
    pub fn reset(&mut self, other: &Self) {
        // Reset the memory
        self.memory.reset(&other.memory);

        // Reset the register
        self.registers = other.registers.clone();
    }

    /// Read a register value from the guest.
    pub fn reg(&self, register: Register) -> u64 {
        self.registers[register as usize]
    }

    /// Set a register value in the guest.
    pub fn set_reg(&mut self, register: Register, value: u64) {
        self.registers[register as usize] = value;
    }

    /// Fork the emulator into a new emulator, copying the current Mmu state.
    pub fn fork(&self) -> Self {
        Emulator {
            memory: self.memory.fork(),
            registers: self.registers.clone(),
        }
    }

    /// Load a file into the emulators address space based on the provided sections.
    pub fn load<P: AsRef<Path>>(&mut self, file_name: P, sections: &[Section]) -> Option<()> {

        // Read the input file from disk
        let contents = std::fs::read(file_name).ok()?;

        // Next, load each section
        for section in sections {
            // Mark the memory as writable so we can load into it
            self.memory.set_permissions(section.virt_addr, section.mem_size, Perm(PERM_WRITE))?;

            // Write the file contents to memory
            self.memory.write_from(section.virt_addr, 
                &contents[section.file_offset..
                          section.file_offset.checked_add(section.file_size)?])?;

            // Pad with zeros
            if section.mem_size > section.file_size {
                let padding = vec![0u8; section.mem_size - section.file_size];
                self.memory.write_from(
                    VirtAddr(section.virt_addr.0.checked_add(section.file_size)?), 
                    &padding);
            }

            // Set the permissions as specified in the Section struct.
            self.memory.set_permissions(section.virt_addr, section.mem_size, section.permissions)?;

            // Update the allocator beyond any sections we load, to ensure this memory can't
            // be allocated again.
            self.memory.cur_alloc = VirtAddr(std::cmp::max(
                    self.memory.cur_alloc.0, 
                    (section.virt_addr.0 + section.mem_size + 0xf) & !0xf
            ));
        }

        Some(())
    }


    pub fn run(&mut self) -> Option<()> {
        loop {
            // Fetch the current PC.
            let pc = self.reg(Register::Pc);
            // Fetch the current instruction
            let inst = mmu_read_perms!(self.memory, VirtAddr(pc as usize), Perm(PERM_EXEC), u32)?;

            let opcode = inst & 0b1111111;

            match opcode {
                // LUI: Load Upper Immediate
                0b0110111 => {

                }

                _ => {panic!("Unknown opcode :(")}
            }

            print!("{:x?}\n", opcode);
        }

//        Some(())
    }
}


