use crate::mmu::{Mmu, VirtAddr};
use crate::riscv;
use crate::files::FilePool;

#[repr(u8)]
pub enum Archs {
    RiscV = 0,
}

pub trait PreArch: Arch {
    fn new(mmu: Mmu, filePool: FilePool) -> Box<dyn Arch + Send + Sync>;
}

pub trait Arch {

    fn tick(&mut self) -> Result<(), VmExit>;
    fn get_register_raw(&self, reg: usize) -> Option<u64>;
    fn set_register_raw(&mut self, reg: usize, value: u64) -> Option<()>;
    fn set_entry(&mut self, value: u64);
    fn set_stackp(&mut self, value: u64);

    fn get_register_state(&self) -> &[u64];
    fn set_register_state(&mut self, new_regs: &[u64]) -> Option<()>;

    fn fork(&self) -> Box<dyn Arch + Send + Sync>;
}

#[derive(Clone, Copy, Debug)]
pub enum VmExit {

    /// Clean exit, as requested by the Guest.
    Exit(i64),

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

    /// Requested memory is out of bounds.
    AddressMiss(VirtAddr, usize),

    /// The VM hit an error during a subroutine, error is not 
    /// necessarily caused by the program.
    Meta,
}

pub struct Emulator {
    /// The architecture struct that this emu will exec.
    pub arch: Box<dyn Arch + Send + Sync>,
}

impl Emulator {
    // Create a new emulator, using a predefined block of memory and a stack size.
    pub fn new(chosen_arch: Archs, mem: Mmu, filePool: FilePool) -> Self {
        match chosen_arch {
            Archs::RiscV => {
                Emulator{
                    arch: riscv::RiscV::new(mem, filePool),
                }
            },
        }
    }

    /// Fork the current emulator.
    pub fn fork(&self) -> Self {
        Emulator {
            arch: self.arch.fork(),
        }
    }

    /// Differentially reset the emulator to a previous state.
    /// Assumes `other` is actually an earlier version of `self`.
    pub fn reset(&mut self, other: &Self) {
        self.arch.set_register_state(other.arch.get_register_state());
    }

    /// Set the entry point of the emulator.
    pub fn set_entry(&mut self, entry: u64) {
        self.arch.set_entry(entry);
    }

    /// Set the stack pointer.
    pub fn set_stackp(&mut self, stackp: u64) {
        self.arch.set_stackp(stackp);
    }

    /// Run the emulator until it either crashes or exits.
    pub fn run(&mut self) -> VmExit {
        loop {
            if let Err(exit) = self.arch.tick(){
        //        DEBUG
        //        println!("VM exited due to: {:?}", exit);
                break exit;
            }
        }
    }
}

