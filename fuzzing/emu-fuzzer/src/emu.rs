use crate::mmu::{Mmu, VirtAddr};
use crate::riscv;
use crate::files::FilePool;

#[repr(u8)]
pub enum Archs {
    RiscV = 0,
}

pub trait PreArch: Arch {
    fn new() -> Box<dyn Arch + Send + Sync>;
}

pub trait Arch {

    fn tick(&mut self, mmu: &mut Mmu, file_pool: &mut FilePool) -> Result<(), VmExit>;
    fn get_register_raw(&self, reg: usize) -> Option<u64>;
    fn set_register_raw(&mut self, reg: usize, value: u64) -> Option<()>;
    fn set_entry(&mut self, value: u64);
    fn set_stackp(&mut self, value: u64);

    fn get_register_state(&self) -> &[u64];
    fn set_register_state(&mut self, new_regs: &[u64]) -> Option<()>;
    fn get_program_counter(&self) -> u64;

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
}

impl VmExit {
    /// Helper function to add some structure to crash definitions
    pub fn is_crash(self) -> Option<(FaultType, VirtAddrType)> {
        match self {
            VmExit::ReadFault(addr, _) => Some((FaultType::Read, addr.into())),
            VmExit::WriteFault(addr, _) => Some((FaultType::Write, addr.into())),
       //     VmExit::ExecFault(addr, _) => Some((FaultType::Exec, addr.into())),
            VmExit::AddressMiss(addr, _) => Some((FaultType::Bounds, addr.into())),
            _ => None,
        }
    }
}


/// Different types of faults
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FaultType {
    Bounds,
    Exec,
    Read,
    Write,
    Uninit,
}


/// Distinguish between different types of addresses for crash deduping
#[derive(Clone, Copy, Debug)]
pub enum VirtAddrType {
    // Address is literally null
    NullAddr,
    // Address is small (0, 32Ki]
    SmallAddr,
    // Address is small and negative [32Ki, 0)
    NegativeAddr,
    // Address is "normal"
    NormalAddr,
}

impl From<VirtAddr> for VirtAddrType {
    fn from(val: VirtAddr) -> Self {
        match val.0 as i64 {
            0           => VirtAddrType::NullAddr,
            1..=32768   => VirtAddrType::SmallAddr,
            -32768..=-1 => VirtAddrType::NegativeAddr,
            _           => VirtAddrType::NormalAddr,
        }
    }
}

pub struct Emulator {
    /// The architecture struct that this emu will exec.
    pub arch: Box<dyn Arch + Send + Sync>,

    /// The Memory management unit for this emulator
    mmu: Mmu,

    /// The file pool from which this emulator can pull files.
    pub file_pool: FilePool,
}

impl Emulator {
    /// Create a new emulator, using a predefined block of memory and a stack size.
    pub fn new(chosen_arch: Archs, mem: Mmu, file_pool: FilePool) -> Self {
        match chosen_arch {
            Archs::RiscV => {
                Emulator{
                    arch     : riscv::RiscV::new(),
                    mmu      : mem,
                    file_pool: file_pool,
                }
            },
        }
    }

    /// Fork the current emulator.
    pub fn fork(&self) -> Self {
        Emulator {
            arch     : self.arch.fork(),
            mmu      : self.mmu.fork(),
            file_pool: self.file_pool.clone(),
        }
    }

    /// Differentially reset the emulator to a previous state.
    /// Assumes `other` is actually an earlier version of `self`.
    pub fn reset(&mut self, other: &Self) {
        self.arch.set_register_state(other.arch.get_register_state());
        self.mmu.reset(&other.mmu);
        self.file_pool.reset();
    }

    /// Set the entry point of the emulator.
    pub fn set_entry(&mut self, entry: u64) {
        self.arch.set_entry(entry);
    }

    /// Set the stack pointer.
    pub fn set_stackp(&mut self, stackp: u64) {
        self.arch.set_stackp(stackp);
    }

    /// Helper function to tick the emu.
    fn tick(&mut self) -> Result<(), VmExit> {
        self.arch.tick(&mut self.mmu, &mut self.file_pool)
    }

    /// Run the emulator until it either crashes or exits.
    pub fn run(&mut self) -> (usize, VmExit) {
        for count in 0.. {
            if let Err(exit) = self.tick() {
                return (count, exit);
            }
        }
        // Did I just solve the halting problem?
        unreachable!();
    }

    /// Run the emulator until a certain instruction. Returns before the instruction
    /// is executed.
    pub fn run_until(&mut self, inst: u64) -> Option<(usize, VmExit)> {
        loop {
            let pc = self.arch.get_program_counter();
            //self.tick().ok()?;
            if let Err(e) = self.tick() {
                return Some((pc as usize, e))
            }
            if self.arch.get_program_counter() == inst {
                //break Some(())
                break Some((inst as usize, VmExit::Exit(0)))
            }
        }
    }
}

