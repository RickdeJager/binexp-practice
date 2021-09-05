use crate::mmu::{Mmu, VirtAddr};
use crate::riscv;
use crate::jitcache::JitCache;
use crate::files::FilePool;

use std::sync::Arc;
use std::process::Command;
use std::collections::BTreeMap;

#[repr(u8)]
pub enum Archs {
    RiscV = 0,
}

pub trait PreArch: Arch {
    fn new() -> Box<dyn Arch + Send + Sync>;
}

pub trait Arch {

    fn tick(&mut self, mmu: &mut Mmu, file_pool: &mut FilePool, break_map: &BreakpointMap)
        -> Result<(), VmExit>;
    fn get_register_raw(&self, reg: usize) -> Option<u64>;
    fn set_register_raw(&mut self, reg: usize, value: u64) -> Option<()>;
    fn set_stackp(&mut self, value: u64);

    fn get_register_state(&self) -> &[u64];
    fn get_register_pointer(&self) -> usize;
    fn set_register_state(&mut self, new_regs: &[u64]) -> Option<()>;
    fn get_program_counter(&self) -> u64;
    fn set_program_counter(&mut self, value: u64);

    fn fork(&self) -> Box<dyn Arch + Send + Sync>;

    fn generate_jit(&mut self, pc: VirtAddr, num_blocks: usize, mmu: &mut Mmu, 
                    break_map: &BreakpointMap) -> Result<String, VmExit>;

    fn handle_syscall(&mut self, mmu: &mut Mmu, file_pool: &mut FilePool) -> Result<(), VmExit>;
}

#[derive(Clone, Copy, Debug)]
pub enum VmExit {

    /// Clean exit, as requested by the Guest.
    Exit(i64),

    /// We reached the end of whatever critical function we're targetting, we can reset here.
    EndOfFuzzCase,

    /// We're exiting for some unspecified reason related to the emulators execution, rather
    /// than guest behaviour.
    Meta,

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

    /// A branch occured to a location outside of the available JIT region.
    JitOob,
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


pub type BreakpointMap = BTreeMap<VirtAddr, BreakpointCallback>;
/// Callback for breakpoints
type BreakpointCallback = fn(&mut Mmu) -> Result<(), VmExit>;

pub struct Emulator {
    /// The architecture struct that this emu will exec.
    pub arch: Box<dyn Arch + Send + Sync>,

    /// The Memory management unit for this emulator
    mmu: Mmu,

    /// The file pool from which this emulator can pull files.
    pub file_pool: FilePool,

    /// (Optional) Reference to shared JIT cache
    pub jit_cache: Option<Arc<JitCache>>,

    /// a Map of breakpoints, keyed by address, containing callback functions to execute when hit
    breakpoints: BreakpointMap,
}

/// Callback functions
/// End the fuzz case, and return some perf counters.
fn end_of_fuzz_case(_: &mut Mmu) -> Result<(), VmExit> {
    // TODO; Return instr exec'd
    Err(VmExit::EndOfFuzzCase)
}

impl Emulator {
    /// Create a new emulator, using a predefined block of memory and a stack size.
    pub fn new(chosen_arch: Archs, mem: Mmu, file_pool: FilePool) -> Self {
        match chosen_arch {
            Archs::RiscV => {
                Emulator{
                    arch       : riscv::RiscV::new(),
                    mmu        : mem,
                    file_pool  : file_pool,
                    jit_cache  : None,
                    breakpoints: BTreeMap::new(),
                }
            },
        }
    }

    /// Add a jitcache and enable JIT for this emu (assuming the arch supports it)
    pub fn add_jitcache(&mut self, jit_cache: Arc<JitCache>) {
        self.jit_cache = Some(jit_cache);
    }

    /// Fork the current emulator.
    pub fn fork(&self) -> Self {
        Emulator {
            arch       : self.arch.fork(),
            mmu        : self.mmu.fork(),
            file_pool  : self.file_pool.clone(),
            jit_cache  : self.jit_cache.clone(),
            breakpoints: self.breakpoints.clone(),
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
        self.arch.set_program_counter(entry);
    }

    /// Set the stack pointer.
    pub fn set_stackp(&mut self, stackp: u64) {
        self.arch.set_stackp(stackp);
    }

    /// Helper function to tick the emu.
    fn tick(&mut self) -> Result<(), VmExit> {
        self.arch.tick(&mut self.mmu, &mut self.file_pool, &self.breakpoints)
    }

    /// Run using either the emu, or a JIT-enabled variant
    pub fn run(&mut self) -> (usize, VmExit) {
        match self.jit_cache {
            None    => self.run_emu(),
            Some(_) => self.run_jit(),
        }
    }



    /// Small helper function to keep the interfacte for run_jit equal to run_emu.
    /// TODO; probably will restructure this later
    pub fn run_jit(&mut self) -> (usize, VmExit) {
        let ret = self.do_run_jit();

        if let Err(e) = ret{
            return (0, e)
        }
        unreachable!("boop");
    }

    /// Run the emulator until it either crashes or exits.
    pub fn run_emu(&mut self) -> (usize, VmExit) {
        for count in 0.. {
            //let pc = self.arch.get_program_counter();
            //println!("PC: {:#x}", pc);
            if let Err(exit) = self.tick() {
                // DEBUG
                return (count, exit);
            }
        }
        // Did I just solve the halting problem?
        unreachable!();
    }

    /// Single step forwards until the emulator is sat at the required instruction.
    pub fn step_until(&mut self, addr: VirtAddr) -> Option<(usize, VmExit)> {
        loop {
            let pc = self.arch.get_program_counter() as usize;
            if pc == addr.0 {
                break Some((pc, VmExit::Meta))
            }
            if let Err(e) = self.tick() {
                break Some((pc, e))
            }
        }
    }

    /// Specify an address where we want to end this fuzz case.
    pub fn set_end_of_fuzz_case(&mut self, addr: VirtAddr) {
        assert!(self.breakpoints.insert(addr, end_of_fuzz_case).is_none());
    }

    /// This functions keeps the JIT choochin' by invoking nasm when needed, and handling
    /// JIT exit's appropriately.
    ///
    /// Returns an Err(VmExit) either due to crash or completion.
    fn do_run_jit(&mut self) -> Result<(), VmExit> {

        let mmu       = &mut self.mmu;
        let file_pool = &mut self.file_pool;
        let jit_cache = self.jit_cache.as_ref().unwrap();

        // Allow the JIT entry point to be overwritten. This is useful for breakpoint / callback
        // handling. This will point to a specific address in host memory.
        let mut overwrite_jit_address: Option<usize> = None;

        // use a temp directory to assemble in.
        let tmpdir = std::env::temp_dir().join("fuzzy");
        std::fs::create_dir_all(&tmpdir).expect("Failed to create tmp dir for JIT cache");
        let thread_id = std::thread::current().id().as_u64();

        loop {
            let pc       = self.arch.get_program_counter();
            let jit_addr = jit_cache.lookup(VirtAddr(pc as usize));

            // Get the addresses we need to run the JIT:
            let (mem, perms, dirty, dirty_bitmap) = mmu.jit_addresses();
            let translation_table = jit_cache.translation_table();

            
            let jit_addr = match (jit_addr, overwrite_jit_address) {
                // If the address is not already in jitcache, and we don't have an overwrite, we
                // have to generate some new assembly and JIT it.
                (None, None) => {
                    // Go through each instruction in the block to emit some x86_64 assembly
                    let asm = self.arch.generate_jit(VirtAddr(pc as usize),
                                                jit_cache.num_blocks(), mmu, &self.breakpoints)?;

                    let asmfn = tmpdir.join(&format!("tmp-{}.asm", thread_id));
                    let binfn = tmpdir.join(&format!("tmp-{}.bin", thread_id));
                    std::fs::write(&asmfn, &asm).expect("Failed to drop ASM to disk");
                    let _nasm_res = Command::new("nasm")
                        .args(&["-f", "bin", "-o", binfn.to_str().unwrap(),
                                asmfn.to_str().unwrap()])
                        .status()
                        .expect("Failed to run `nasm`, is it in your PATH?");

                    // Read the binary that nasm just generated for us.
                    let tmp = std::fs::read(binfn).expect("Failed to read NASM output.");

                    // Add the fresh JIT code to the mapping.
                    jit_cache.add_mapping(VirtAddr(pc as usize), &tmp)
                },

                // If we already have JIT cache for our destination, and we don't have an overwrite
                // set, we can just return the cached location.
                (Some(jit_addr), None) => {
                    jit_addr
                },

                // If we have an overwrite_jit_address set, ignore whatever jit_addr is, and force
                // the return value to be the overwrite address.
                (_, Some(new_addr)) => {
                    // Clear out the overwrite, so subsequent runs will resolve a proper address.
                    overwrite_jit_address = None;
                    new_addr
                },
            };

            let mut num_dirty_inuse = mmu.dirty_len();
            let exit_code: u64;
            let reentry  : u64;
            let arg1     : u64;

            unsafe {

                // Hop into the JIT
                asm!(r#"
                   call {entry}
                "#,
                entry = in(reg) jit_addr,
                in("r8")  mem,
                in("r9")  perms,
                in("r10") dirty,
                in("r11") dirty_bitmap,
                inout("r12") num_dirty_inuse,
                in("r13") self.arch.get_register_pointer(),
                in("r14") translation_table,
                // Let rust known what we potentially clobbered.
                out("rax") exit_code,
                out("rdx") reentry,
                out("rcx") arg1,
                );

                // Update the length of the dirty list, since we potentially added some items
                // to its backing store.
                mmu.set_dirty_len(num_dirty_inuse);
            }

            // DEBUG
            //println!("JIT exited with {:#x}, reentry: {:#x}", exit_code, reentry);
            match exit_code {
                1 => {
                    // Branch decode request, update PC and re-JIT
                    self.arch.set_program_counter(reentry)
                },
                2 => {
                    // JIT encountered a syscall. Handle it and reenter.
                    // (We need to set PC first, so a syscall can potentially set PC as well,
                    //  like `sigreturn` for example.)
                    self.arch.set_program_counter(reentry);
                    self.arch.handle_syscall(mmu, file_pool)?;
                },
                4 => {
                   // JIT encountered a read fault, let the fuzzer known we crashed.
                   // TODO; 
                   // - We don't currently pass the read size. Assuming 1 for now
                   // - The crash_handler will request pc to dedupe crashes, which will be
                   //   slightly off, due to lazy updating.
                   //   Setting it here is a bit hacky
                   //
                   //   Arg1 contains the offending address
                   self.arch.set_program_counter(reentry);
                   return Err(VmExit::ReadFault(VirtAddr(arg1 as usize), 1))
                },
                5 => {
                   // JIT encountered a write fault, let the fuzzer known we crashed.
                   // TODO; 
                   // - We don't currently pass the read size. Assuming 1 for now
                   // - The crash_handler will request pc to dedupe crashes, which will be
                   //   slightly off, due to lazy updating.
                   //   Setting it here is a bit hacky
                   //
                   //   Arg1 contains the offending address
                   self.arch.set_program_counter(reentry);
                   return Err(VmExit::ReadFault(VirtAddr(arg1 as usize), 1))
                },
                6 => {
                    // JIT encountered a breakpoint, probably because we injected one.'
                    // Check if the breakpoint is one of ours, and if so handle the callback.
                    if let Some(callback) = self.breakpoints.get(&VirtAddr(reentry as usize)) {
                        // This callback can potentially stop execution here.
                        callback(mmu)?;
                    }
                    // If all is well jump back into the JIT code, but force a new entry point so
                    // we don't end up in an endless loop of breakpoints and despair.
                    overwrite_jit_address = Some(arg1 as usize);
                }
                x => unimplemented!("JIT Exit code not handled: {}.", x),
            }
        }
       // Err(VmExit::Exit(-1))
    }


}

