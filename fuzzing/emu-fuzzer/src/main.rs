#[allow(dead_code)]

#[macro_use]
// MMU defines macro's for reading/writing integer types, so must be pulled in
// before any other modules are pulled in.
mod mmu;
mod emu;
mod riscv;
mod syscall;

use mmu::{Mmu, Perm, VirtAddr};
use mmu::{PERM_WRITE, PERM_READ, PERM_EXEC};
use emu::{Emulator, Archs};


/// Load an elf, return the entry point on success.
fn load_elf(binary_path: &str, mmu: &mut Mmu) -> Option<u64> {
    // Read the input file from disk
    let contents = std::fs::read(binary_path).ok()?;

    let binary = goblin::elf::Elf::parse(&contents).ok()?;
    let entry = binary.entry;
    for ph in binary.program_headers {
        match ph.p_type {
            goblin::elf::program_header::PT_LOAD => {
                let virtaddr    = VirtAddr(ph.p_vaddr as usize);
                let mem_size    = ph.p_memsz  as usize;
                let file_size   = ph.p_filesz as usize;
                let file_offset = ph.p_offset as usize;
                mmu.set_permissions(virtaddr, mem_size, Perm(PERM_WRITE))?;

                // Write the file contents to memory
                mmu.write_from(virtaddr, 
                    &contents[file_offset..file_offset.checked_add(file_size)?]).ok()?;

                // Pad with zeros
                if mem_size > file_size {
                    let padding = vec![0u8; mem_size - file_size];
                    mmu.write_from( VirtAddr(virtaddr.0.checked_add(file_size)?), &padding).ok()?;
                }

                let mut permissions = Perm(0);
                // Translate Goblin perms to our custom Perms
                if ph.p_flags & goblin::elf::program_header::PF_X != 0 
                    {permissions.0 |= PERM_EXEC};
                if ph.p_flags & goblin::elf::program_header::PF_W != 0
                    {permissions.0 |= PERM_WRITE};
                if ph.p_flags & goblin::elf::program_header::PF_R != 0
                    {permissions.0 |= PERM_READ};

                // Set the permissions as specified in the Section struct.
                mmu.set_permissions(virtaddr, mem_size, permissions)?;

                // Update the allocator beyond any sections we load, to ensure this memory can't
                // be allocated again.
                mmu.cur_alloc = VirtAddr(std::cmp::max(
                        mmu.cur_alloc.0, 
                        (virtaddr.0 + mem_size + 0xf) & !0xf
                ));
            },
            _ => ()
        }
    }

    Some(entry)
}

fn main() {
    let binary_path = "./riscv/minimal";
    let mmu_size = 1024 * 1024;
    let mut memory = Mmu::new(mmu_size);
    let entryp = load_elf(binary_path, &mut memory).expect("Failed to parse ELF.");
    // Create a stack
    let mut stack = memory.allocate(32 * 1024).expect("Failed to allocate stack.");

    // TODO; This is terrible, but will revisit later.
    let tmp8  = [0u8; 8];
    let tmp16 = [0u8; 16];
    stack.0 -= 8;
    memory.write_from(stack, &tmp8).unwrap(); // ARGC
    stack.0 -= 16;
    memory.write_from(stack, &tmp16).unwrap(); // ARGV
    stack.0 -= 16;
    memory.write_from(stack, &tmp16).unwrap(); // ARGP
    stack.0 -= 16;
    memory.write_from(stack, &tmp16).unwrap(); // AUXP
    stack.0 -= 16;
    memory.write_from(stack, &tmp16).unwrap();


    let mut emu = Emulator::new(Archs::RiscV, memory.fork());

    // Set the emu's entry point
    emu.set_entry(entryp);
    // Set the emu's stack pointer to point to our newly created stack pointer
    emu.set_stackp(stack.0 as u64 - 8u64);

    emu.run();


}
