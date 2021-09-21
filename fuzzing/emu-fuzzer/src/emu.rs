use crate::mmu::{Mmu, VirtAddr, Perm, PERM_READ, PERM_WRITE};
use crate::Rng;
use crate::riscv;
use crate::jitcache::JitCache;
use crate::files::{FilePool, Corpus};
use crate::MAX_INSTRUCTIONS;

use std::sync::Arc;
use std::process::Command;
use std::collections::{BTreeMap, HashMap};

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
    fn set_return_value(&mut self, value: u64);
    fn get_function_arguments(&mut self) -> (u64, u64, u64);
    fn do_return(&mut self);

    fn get_register_state(&self) -> &[u64];
    fn get_register_pointer(&self) -> usize;
    fn set_register_state(&mut self, new_regs: &[u64]) -> Option<()>;
    fn get_program_counter(&self) -> u64;
    fn set_program_counter(&mut self, value: u64);

    fn fork(&self) -> Box<dyn Arch + Send + Sync>;

    fn generate_jit(&mut self, pc: VirtAddr, num_blocks: usize, mmu: &mut Mmu, 
                    break_map: &BreakpointMap, corpus: &Corpus, file_pool: &FilePool)
        -> Result<String, VmExit>;

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

    /// We hit the maximum number of fuzz cases allowed before hitting another exit reason.
    TimeOut,

    /// Calling this Syscall would trigger an integer overflow.
    SyscallIntegerOverflow,

    /// An overflow was triggered while calculating calloc size
    CallocOverflow,

    /// The VM attempted to free a chunk of memory that was either already free'd, or never
    /// allocated in the first place.
    InvalidFree(VirtAddr),

    /// The VM called a syscall that we don't have a handler for.
    SyscallNotImplemented(u64),

    /// A Read fault occured at `addr` with `length`.
    ReadFault(VirtAddr, usize),

    /// The VM tried to decode NX memory at `addr` with `length` as an executable instruction.
    ExecFault(VirtAddr, usize),

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
            VmExit::ReadFault(addr, _)   => Some((FaultType::Read, addr.into())),
            VmExit::WriteFault(addr, _)  => Some((FaultType::Write, addr.into())),
            VmExit::ExecFault(addr, _)   => Some((FaultType::Exec, addr.into())),
            VmExit::AddressMiss(addr, _) => Some((FaultType::Bounds, addr.into())),
            VmExit::InvalidFree(addr)    => Some((FaultType::Free, addr.into())),
            // TODO; Ew
            VmExit::CallocOverflow => Some((FaultType::Alloc, VirtAddr(0).into())),
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
    Alloc,
    Free,
}


/// Distinguish between different types of addresses for crash deduping
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
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


type ArchBox = Box<dyn Arch + Send + Sync>;
pub type BreakpointMap = BTreeMap<VirtAddr, BreakpointCallback>;
/// Callback for breakpoints
type BreakpointCallback = fn(&mut Emulator) -> Result<(), VmExit>;

pub struct Emulator {
    /// The architecture struct that this emu will exec.
    pub arch: ArchBox,

    /// The Memory management unit for this emulator
    mmu: Mmu,

    /// The file pool from which this emulator can pull files.
    pub file_pool: FilePool,

    /// A corpus ref containing all files, and derived files based on coverage/crashes
    pub corpus: Arc<Corpus>,

    /// (Optional) Reference to shared JIT cache
    pub jit_cache: Option<Arc<JitCache>>,

    /// a Map of breakpoints, keyed by address, containing callback functions to execute when hit
    breakpoints: BreakpointMap,
}

/// Callback functions
/// End the fuzz case, and return some perf counters.
fn end_of_fuzz_case(_: &mut Emulator) -> Result<(), VmExit> {
    // TODO; Return instr exec'd
    Err(VmExit::EndOfFuzzCase)
}

fn do_malloc(emu: &mut Emulator) -> Result<(), VmExit> {
    let size = emu.arch.get_function_arguments().0 as usize;

    // Try to perform an allocation, return either its address or NULL.
    let alloc_addr = match emu.mmu.allocate(size) {
            Some(alloc) => {
                // Add this allocation to the malloc set
                assert!(emu.mmu.malloc_map.insert(alloc, size).is_none(), "Double alloc?");
                alloc.0 as u64
            },
            None => 0,
    };

    // DEBUG
    //println!("malloc({:#x}) = {:#x}", size, alloc_addr);

    emu.arch.set_return_value(alloc_addr);
    // Return before doing any malloc internals.
    emu.arch.do_return();
    Ok(())
}

fn do_calloc(emu: &mut Emulator) -> Result<(), VmExit> {
    let (elem_num, elem_size, _) = emu.arch.get_function_arguments();

    // Perform the multiplication first, and only if it succeeds, move on to the allocation.
    let alloc_addr = match elem_num.checked_mul(elem_size) {
        Some(size) => {
            match emu.mmu.allocate_perms(size as usize, Perm(PERM_READ | PERM_WRITE)) {
                Some(alloc) => {
                    // Add this allocation to the malloc set
                    assert!(emu.mmu.malloc_map.insert(alloc, size as usize).is_none(),
                                "Double alloc?");
                    alloc.0 as u64
                },
                None => 0,
            }
        },
        None => {
            return Err(VmExit::CallocOverflow);
        }
    };


    // DEBUG
    //println!("calloc({:#x}) = {:#x}", alloc_addr, alloc_addr);

    // Set the return value for calloc.
    emu.arch.set_return_value(alloc_addr);
    // Return before doing any calloc internals.
    emu.arch.do_return();
    Ok(())
}

fn do_free(emu: &mut Emulator) -> Result<(), VmExit> {
    let addr = VirtAddr(emu.arch.get_function_arguments().0 as usize);

    // free(NULL) is defined as a NO-OP.
    if addr.0 == 0 {
        return Ok(());
    }

    // DEBUG
    //println!("free({:#x})", addr.0);

    // Remove the allocation from the set, so we can catch a double free.
    match emu.mmu.malloc_map.remove(&addr) {
        Some(size) => {
            // If we successfully free'd the memory, remove all permissions from it, s.t.
            // we can catch UAF's
            emu.mmu.set_permissions(addr, size, Perm(0));
        },
        None => {
            // If the allocation was _not_ present, we just caught an invalid free.
            return Err(VmExit::InvalidFree(addr));
        },
    }


    // Return before doing free internals
    emu.arch.do_return();
    Ok(())
}

impl Emulator {
    /// Create a new emulator, using a predefined block of memory and a stack size.
    pub fn new(chosen_arch: Archs, mem: Mmu, corpus: Arc<Corpus>,
               symbols: &HashMap<String, VirtAddr>) -> Self {

        let mut emu = match chosen_arch {
            Archs::RiscV => {
                Emulator{
                    arch       : riscv::RiscV::new(),
                    mmu        : mem,
                    file_pool  : FilePool::new(),
                    corpus     : corpus,
                    jit_cache  : None,
                    breakpoints: BTreeMap::new(),
                }
            },
        };

        if crate::HOOK_ALLOCATIONS {
            emu.configure_hooks(symbols);
        }
        emu
    }

    fn configure_hooks(&mut self, symbols: &HashMap<String, VirtAddr>) {
        // Configure hooks and breakpoints
        let p_malloc = symbols.get("_malloc_r").unwrap();
        self.breakpoints.insert(*p_malloc, do_malloc);
        println!("hooked malloc: {:#x}", p_malloc.0);

        /*
        let p_calloc = symbols.get("_calloc_r").unwrap();
        self.breakpoints.insert(*p_calloc, do_calloc);
        println!("hooked calloc: {:#x}", p_calloc.0);
        */

        let p_free = symbols.get("_free_r").unwrap();
        self.breakpoints.insert(*p_free, do_free);

        println!("hooked free: {:#x}", p_free.0);

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
            corpus     : self.corpus.clone(),
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

    /// Run the emulator until it either crashes or exits.
    pub fn run_emu(&mut self) -> (usize, VmExit) {
        for count in 0..MAX_INSTRUCTIONS {

            // Track coverage
            let pc = self.arch.get_program_counter() as usize;
            self.corpus.code_coverage.entry_or_insert(&VirtAddr(pc), pc, || {
                // If this PC wasn't seen before, save the input file.
                self.corpus.add_input(self.file_pool.get_file_ref());
                Box::new(())
            });

            // DEBUG
            //println!("Pc: {:#x}", pc);

            // Resolve breakpoints
            if let Some(callback) = self.breakpoints.get(&VirtAddr(pc)) {
                // The callback might cause an exit
                if let Err(exit) = callback(self) {
                    return (count, exit);
                }
            }

            if let Err(exit) = self.tick() {
                return (count, exit);
            }
        }

        return (MAX_INSTRUCTIONS, VmExit::TimeOut)
    }

    /// Single step forwards until the emulator is sat at the required instruction.
    /// TODO; Rework this interface
    pub fn step_until(&mut self, addr: VirtAddr) -> Option<()> {
        self.set_end_of_fuzz_case(addr);
        self.run_emu();
        self.breakpoints.remove(&addr);
        if self.arch.get_program_counter() == addr.0 as u64 {
            return Some(())
        }
        None
    }

    /// Specify an address where we want to end this fuzz case.
    pub fn set_end_of_fuzz_case(&mut self, addr: VirtAddr) {
        assert!(self.breakpoints.insert(addr, end_of_fuzz_case).is_none());
    }

    /// Prepare the emulator for its next fuzz case, and optionally add some corruption.
    pub fn randomize(&mut self, rng: &mut Rng, max_tweaks: usize) {
        self.file_pool.randomize(rng, max_tweaks, &*self.corpus);
    }

    /// This functions keeps the JIT choochin' by invoking nasm when needed, and handling
    /// JIT exit's appropriately.
    ///
    /// Returns an Err(VmExit) either due to crash or completion.
    fn run_jit(&mut self) -> (usize, VmExit) {

        // Keep track of the total number of instructions executed in this JIT run, by this
        // specific emulator.
        let mut total_emu_instructions = 0usize;

        // Allow the JIT entry point to be overwritten. This is useful for breakpoint / callback
        // handling. This will point to a specific address in host memory.
        let mut overwrite_jit_address: Option<usize> = None;

        // use a temp directory to assemble in.
        let tmpdir = std::env::temp_dir().join("fuzzy");
        std::fs::create_dir_all(&tmpdir).expect("Failed to create tmp dir for JIT cache");
        let thread_id = std::thread::current().id().as_u64();

        loop {
            let pc        = self.arch.get_program_counter();
            let jit_cache = self.jit_cache.as_ref().unwrap();
            let jit_addr  = jit_cache.lookup(VirtAddr(pc as usize));

            // DEBUG
            //println!("JIT PC {:#x}", pc);

            // Get the addresses we need to run the JIT:
            let (mem, perms, dirty, dirty_bitmap) = self.mmu.jit_addresses();
            let translation_table = jit_cache.translation_table();

            
            let jit_addr = match (jit_addr, overwrite_jit_address) {
                // If the address is not already in jitcache, and we don't have an overwrite, we
                // have to generate some new assembly and JIT it.
                (None, None) => {
                    // Go through each instruction in the block to emit some x86_64 assembly
                    let jit_ret = self.arch.generate_jit(VirtAddr(pc as usize), 
                                                         jit_cache.num_blocks(), &mut self.mmu,
                                                         &self.breakpoints, &*self.corpus,
                                                         &self.file_pool);
                    if let Err(e) = jit_ret {
                        // If we hit and error during jit generation, exit here.
                        return (total_emu_instructions, e);
                    };

                    // We just handled the error case, so we can unwrap here.
                    let asm = jit_ret.unwrap();
                    // For easier debugging, remove the indentation.
                    let asm = str::replace(&asm, "  ", "");

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

            let mut num_dirty_inuse = self.mmu.dirty_len();
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
                inout("r15") total_emu_instructions,
                // Let rust known what we potentially clobbered.
                out("rax") exit_code,
                out("rdx") reentry,
                out("rcx") arg1,
                );

                // Update the length of the dirty list, since we potentially added some items
                // to its backing store.
                self.mmu.set_dirty_len(num_dirty_inuse);
            }

            // DEBUG
            //println!("JIT exited with {:#x}, reentry: {:#x}", exit_code, reentry);

            // Handle the JIT exit code and potentially end the fuzz case
            let ret = match exit_code {
                1 => {
                    // Branch decode request, update PC and re-JIT
                    self.arch.set_program_counter(reentry);
                    Ok(())
                },
                2 => {
                    // JIT encountered a syscall. Handle it and reenter.
                    // (We need to set PC first, so a syscall can potentially set PC as well,
                    //  like `sigreturn` for example.)
                    self.arch.set_program_counter(reentry);
                    self.arch.handle_syscall(&mut self.mmu, &mut self.file_pool)
                },
                3 => {
                    // JIT encountered a breakpoint, probably because we injected one.'
                    // Check if the breakpoint is one of ours, and if so handle the callback.
                    let mut ret = Ok(());
                    self.arch.set_program_counter(reentry);

                    // If all is well, we will jump back into the JIT code, but we need to specify 
                    // a new entry point so we don't end up in an endless loop of breakpoints 
                    // and despair. (in case we exit, this won't matter)
                    //
                    // Keep in mind, this is a "host" address, pointing into the block of jit mem.
                    overwrite_jit_address = Some(arg1 as usize);

                    if let Some(callback) = self.breakpoints.get(&VirtAddr(reentry as usize)) {
                        // This callback can potentially stop execution here.
                        if let Err(e) =  callback(self) {
                            ret = Err(e);
                        } else {
                            // If the callback passed without error, check whether we set
                            // a new PC. If we did, we need to make sure we don't follow the
                            // overwrite address.
                            if reentry != self.arch.get_program_counter() {
                                overwrite_jit_address = None;
                            }
                        }
                    }
                    ret
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
                   Err(VmExit::ReadFault(VirtAddr(arg1 as usize), 1))
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
                   Err(VmExit::ReadFault(VirtAddr(arg1 as usize), 1))
                },
                6 => {
                   // JIT encountered a write timeout, we decide to end the fuzz case here.
                   self.arch.set_program_counter(reentry);
                   Err(VmExit::TimeOut)
                },
                x => unimplemented!("JIT Exit code not handled: {}.", x),
            };

            // If we hit some reason to exit, return and include the number of instructions
            // executed during this JIT session.
            if let Err(e) = ret {
                return (total_emu_instructions, e)
            }
        }
    }
}

