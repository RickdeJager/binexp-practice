use crate::mmu::{Mmu, VirtAddr};
use crate::riscv;
use crate::Rng;
use crate::files::FilePool;

#[repr(u8)]
pub enum Archs {
    RiscV = 0,
}

pub trait PreArch: Arch {
    fn new(mmu: Mmu, file_pool: FilePool) -> Box<dyn Arch + Send + Sync>;
}

pub trait Arch {

    fn tick(&mut self) -> Result<(), VmExit>;
    fn get_register_raw(&self, reg: usize) -> Option<u64>;
    fn set_register_raw(&mut self, reg: usize, value: u64) -> Option<()>;
    fn set_entry(&mut self, value: u64);
    fn set_stackp(&mut self, value: u64);

    fn get_register_state(&self) -> &[u64];
    fn set_register_state(&mut self, new_regs: &[u64]) -> Option<()>;
    fn get_program_counter(&self) -> u64;

    fn fork(&self) -> Box<dyn Arch + Send + Sync>;
    fn reset_mem(&mut self, other_mem: &Mmu);
    fn reset_filepool(&mut self);
    fn get_mem_ref(&self) -> &Mmu;
    fn get_filepool_ref(&self) -> &FilePool;

    fn apply_random_tweak(&mut self, r: &mut Rng, corruption: usize) -> Option<()>;
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
    pub fn new(chosen_arch: Archs, mem: Mmu, file_pool: FilePool) -> Self {
        match chosen_arch {
            Archs::RiscV => {
                Emulator{
                    arch: riscv::RiscV::new(mem, file_pool),
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
        self.arch.reset_mem(other.arch.get_mem_ref());
        self.arch.reset_filepool();
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
    pub fn run(&mut self) -> (usize, VmExit) {
        for count in 0.. {
            if let Err(exit) = self.arch.tick(){
                return (count, exit);
            }
        }
        unreachable!();
    }

    /// Run the emulator until a certain instruction. Returns before the instruction
    /// is executed.
    pub fn run_until(&mut self, inst: u64) -> Option<()> {
        loop {
            self.arch.tick().ok()?;
            if self.arch.get_program_counter() == inst {
                break Some(())
            }
        }
    }
}

