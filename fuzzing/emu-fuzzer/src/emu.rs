use std::path::Path;

use crate::mmu::{Mmu, Perm, VirtAddr};
use crate::{Section};
use crate::mmu::{PERM_WRITE, PERM_READ, PERM_RAW, PERM_EXEC};


pub struct Emulator {
    /// The memory belonging to this emu
    pub memory: Mmu    
}

impl Emulator {
    /// Create a new emulator with `size` bytes of memory
    pub fn new(size: usize) -> Self {
        Emulator {
            memory: Mmu::new(size),
        }
    }

    /// Fork the emulator into a new emulator, copying the current Mmu state.
    pub fn fork(&self) -> Self {
        Emulator {
            memory: self.memory.fork(),
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
}


