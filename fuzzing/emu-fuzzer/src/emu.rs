use std::path::Path;

use crate::Section;
use crate::mmu::{Mmu, Perm, VirtAddr, PERM_WRITE};
use crate::riscv;

#[repr(u8)]
pub enum Archs {
    RiscV = 0,
}

pub trait PreArch: Arch {
    fn new(mem: Mmu) -> Box<Self>;
    fn fork(old_arch: &dyn Arch) -> Box<Self>;
}

pub trait Arch {
    fn tick(&mut self) -> Result<(), VmExit>;
    fn get_register_raw(&self, reg: usize) -> Option<u64>;
    fn set_register_raw(&mut self, reg: usize, value: u64) -> Option<()>;
    fn set_entry(&mut self, value: u64);
    fn set_stackp(&mut self, value: u64);

    fn get_register_state(&self) -> &[u64];
    fn set_register_state(&mut self, new_regs: &[u64]) -> Option<()>;

    fn fork_memory(&self) -> Mmu;
}

pub struct Loader {
    /// The memory to load sections in to
    pub memory: Mmu,
}


impl Loader {
    /// Create a new emulator with `size` bytes of memory
    pub fn new(size: usize) -> Self {
        let mem = Mmu::new(size);
        Loader {
            memory: mem,
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
                          section.file_offset.checked_add(section.file_size)?]).ok()?;

            // Pad with zeros
            if section.mem_size > section.file_size {
                let padding = vec![0u8; section.mem_size - section.file_size];
                self.memory.write_from(
                    VirtAddr(section.virt_addr.0.checked_add(section.file_size)?), 
                    &padding).ok()?;
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
}

#[derive(Clone, Copy, Debug)]
pub enum VmExit {

    /// Clean exit, as requested by the Guest.
    Exit(u64),

    /// Calling this Syscall would trigger an integer overflow.
    SyscallIntegerOverflow,

    /// The VM called a syscall that we don't have a handler for.
    SyscallNotImplemented(u64),

    /// A Read fault occured at `addr` with `length`.
    ReadFault(VirtAddr, usize),

    /// A Write fault occured at `addr` with `length`.
    WriteFault(VirtAddr, usize),

    /// The Address overflowed while reading/writing.
    AddressIntegerOverflow,

    /// Requested memomry is out of bounds.
    AddressMiss(VirtAddr, usize),
}

pub struct Emulator {
    /// The architecture struct that this emu will exec.
    pub arch:   Box<dyn Arch>,
}

impl Emulator {
    // Create a new emulator, using a predefined block of memory and a stack size.
    pub fn new(chosen_arch: Archs, mem: Mmu) -> Self {
        match chosen_arch {
            Archs::RiscV => {
                Emulator{
                    arch: riscv::RiscV::new(mem)
                }
            },
        }
    }

    pub fn set_entry(&mut self, entry: u64) {
        self.arch.set_entry(entry);
    }

    pub fn set_stackp(&mut self, stackp: u64) {
        self.arch.set_stackp(stackp);
    }

    pub fn run(&mut self) {
        let exit = loop {
            if let Err(exit)  = self.arch.tick(){
                break exit;
            }
        };

        println!("VM exited due to: {:?}", exit);
    }
}



