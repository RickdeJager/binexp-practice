mod mmu;
mod emu;

use mmu::{Perm, VirtAddr};
use mmu::{PERM_WRITE, PERM_READ, PERM_RAW, PERM_EXEC};
use emu::{Emulator};


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
    let mut emu = Emulator::new(1024*1024);
    emu.load("./riscv/minimal", &[
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

    let mut tmp = [0u8; 4];
    emu.memory.read_into(VirtAddr(0x100c8), &mut tmp);
    print!("{:x?}\n", emu.memory.cur_alloc);
    print!("{:x?}\n", tmp);

}
