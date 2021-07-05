#[allow(dead_code)]

mod mmu;
mod emu;
#[macro_use]
mod riscv;

use mmu::{Perm, VirtAddr};
use mmu::{PERM_WRITE, PERM_READ, PERM_EXEC};
use emu::{Loader, Emulator, Archs};


pub struct Section {
    file_offset: usize,
    virt_addr  : VirtAddr,
    file_size  : usize,
    mem_size   : usize,
    permissions: Perm,
}

fn main() {

/*
 * readelf -l minimal
Elf file type is EXEC (Executable file)
Entry point 0x100c8
There are 2 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  LOAD           0x0000000000000000 0x0000000000010000 0x0000000000010000
                 0x00000000000005b8 0x00000000000005b8  R E    0x1000
  LOAD           0x00000000000005b8 0x00000000000115b8 0x00000000000115b8
                 0x0000000000000780 0x00000000000007b8  RW     0x1000

 Section to Segment mapping:
  Segment Sections...
   00     .text 
   01     .eh_frame .init_array .fini_array .data .sdata .bss 

*/
    let mut loader = Loader::new(1024*1024);
    loader.load("./riscv/minimal", &[
             Section {
                file_offset: 0x0000000000000000,
                virt_addr  : VirtAddr(0x0000000000010000),
                file_size  : 0x00000000000005b8,
                mem_size   : 0x00000000000005b8,
                permissions: Perm(PERM_READ | PERM_EXEC),
             },
             Section {
                file_offset: 0x00000000000005b8,
                virt_addr  : VirtAddr(0x00000000000115b8),
                file_size  : 0x0000000000000780,
                mem_size   : 0x00000000000007b8,
                permissions: Perm(PERM_READ | PERM_WRITE),
             },
    ]).unwrap();

    // Create a stack
    let mut stack = loader.memory.allocate(32 * 1024).expect("Failed to allocate stack.");

    // TODO; This is terrible, but will revisit later.
    let tmp8  = [0u8; 8];
    let tmp16 = [0u8; 16];
    stack.0 -= 8;
    loader.memory.write_from(stack, &tmp8).unwrap(); // ARGC
    stack.0 -= 16;
    loader.memory.write_from(stack, &tmp16).unwrap(); // ARGV
    stack.0 -= 16;
    loader.memory.write_from(stack, &tmp16).unwrap(); // ARGP
    stack.0 -= 16;
    loader.memory.write_from(stack, &tmp16).unwrap(); // AUXP
    stack.0 -= 16;
    loader.memory.write_from(stack, &tmp16).unwrap();


    let mut emu = Emulator::new(Archs::RiscV, loader.memory.fork());

    // Set the emu's entry point
    emu.set_entry(0x100c8);
    // Set the emu's stack pointer to point to our newly created stack pointer
    emu.set_stackp(stack.0 as u64 - 8u64);

    emu.run();


}
