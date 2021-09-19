#![feature(asm, thread_id_value)]
#[macro_use]
// MMU defines macro's for reading/writing integer types, so must be pulled in
// before any other modules are pulled in.
mod mmu;
mod emu;
mod riscv;
mod util;
mod syscall;
mod files;
mod jitcache;

use std::fs;
use mmu::{Mmu, VirtAddr};
use emu::{Emulator, Archs, FaultType, VirtAddrType, VmExit};
use files::Corpus;
use util::load_elf;
use jitcache::JitCache;

use std::time::{Duration, Instant};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, AtomicU64, Ordering};

pub const ALLOW_GUEST_PRINT: bool = false;
pub const ONE_SHOT: bool = false;

pub const DO_SNAPSHOT: bool = true;
pub const END_EARLY: bool = true;
pub const MAX_INSTRUCTIONS: usize = 5_000_000;

pub const FORCE_INTERPRETER: bool = false;

// I/O settings
pub const CRASHES_DIR: &str = "./crashes";
pub const CORPUS_DIR : &str = "./corpus";
pub const TEST_FILE : &str = "testfile";

// Statistics
const BATCH_SIZE: usize = 80;
const NUM_THREADS: usize = 4;

// Fuzzy tweakables
const CORRUPTION_AMOUNT: usize = 16;
const SWAP_RATE: usize = 1;

pub struct Rng(u64);

impl Rng {
    // Constructor
    fn new(extra_seed: u64) -> Self {
       Rng(0x4141414141 ^ extra_seed) 
    }

    // XOR Shift
    #[inline]
    fn rand(&mut self) -> usize {
        let val = self.0;
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 43;

        val as usize
    }
}

#[derive(Default)]
pub struct Stats {
    /// Total number of cycles spent by a VM
    total_cycles: AtomicU64,

    /// Total number of cycles spent on mutation
    mut_cycles: AtomicU64,

    /// Total number of cycles spent on VM operation
    vm_cycles: AtomicU64,

    /// Total number of cycles spent resetting / mutating
    reset_cycles: AtomicU64,

    /// Total number of fuzz cases performed
    fuzz_cases: AtomicUsize,

    /// Total number of crashes
    crashes: AtomicUsize,

    /// Total number of instructions executed
    instructions: AtomicUsize,
}

fn main() {
    let binary_path = "./riscv/targets/TinyEXIF/tiny_exif";
    let corpus_dir  = "./corpus/";
    let mmu_size    = 1024 * 1024 * 8;
    let stack_size  = 1024 * 1024 * 3;
    let mut memory  = Mmu::new(mmu_size);

    // Read input binary from disk.
    let binary_contents = std::fs::read(binary_path).ok().expect("Failed to find ELF.");

    // Parse the binary, load it into the mmu and find its entrypoint
    let (entryp, _binary) = load_elf(&binary_contents, &mut memory).expect("Failed to parse ELF.");


    ////////////////////////
    ///// Stack setup
    ////////////////////////

    // Create a stack
    let mut stack = memory.allocate_stack(stack_size).expect("Failed to allocate stack.");

    /// Push an integer onto the stack
    macro_rules! push_i {
        ($a: expr) => {
            let tmp = $a.to_le_bytes();
            stack.0 -= tmp.len();
            memory.write_from(stack, &tmp).expect("Failed to push to stack.");
        }
    }

    let argv = vec![binary_path, TEST_FILE];

    // AUXP is used by the OS to pass in some auxilary values, like pid, randomness (for canary), 
    // entry point, processor capabilities, ...
    //
    // glibc crashes if AT_RANDOM is not set, and canaries are enabled so this is not optional.
    let randomness = &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 
                       0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let ptr_random = memory.allocate(16).expect("Failed to allocate for AT_RANDOM");
    memory.write_from(ptr_random, randomness).expect("Failed to write AT_RANDOM");
    let auxv = [
        (25u64, ptr_random.0 as u64),   // AT_RANDOM
    ];

    push_i!(0u64); // End AUXV by setting AT_NULL to 0
    push_i!(0u64);

    // Setup AUXV with actual key value pairs.
    for &(num, value) in auxv.iter().rev() {
        push_i!(value);
        push_i!(num);
    }

    push_i!(0u64); // ENVP -> We're using an empty environment for now.
    push_i!(0u64); // ARGV-end

    // Create argv from a vec.
    for &item in argv.iter().rev() {
        let tmp = item.as_bytes();
        // Some functions like strlen, will batch read values, so we need to pad to the
        // next 0x1f alligned string length.
        let alloc_len = (tmp.len() + 1 + 0x1f) & !0x1f;
        // Alloc some space for this argument
        let arg = memory.allocate(alloc_len).expect("Failed to allocate argument");

        memory.write_from(arg, tmp).expect("Failed to write argument");
        // Null terminate and add padding (which clears RAW bit)
        memory.write_from(VirtAddr(arg.0 + tmp.len()), &vec![0u8; alloc_len - tmp.len()])
            .expect("Failed to terminate argument");

        // push the argv pointer onto the stack
        push_i!(arg.0);
    }
    push_i!(argv.len() as u64); // ARGC


    ////////////////////////
    ///// Emulator setup
    ////////////////////////

    // Create a corpus:
    let corpus = Arc::new(Corpus::new(corpus_dir)
                    .expect("Failed to load real file from disk."));

    let mut golden_emu = Emulator::new(Archs::RiscV, memory, corpus.clone());
    // TODO; this is gross. (We need to select an initial file for pre-run or one-shot)
    golden_emu.randomize(&mut Rng::new(0), CORRUPTION_AMOUNT);

    if !FORCE_INTERPRETER {
        let jit_cache  = Arc::new(JitCache::new(VirtAddr(mmu_size)));
        golden_emu.add_jitcache(jit_cache);
    }

    // Set the emu's entry point
    golden_emu.set_entry(entryp);
    // Set the emu's stack pointer to point to our newly created stack pointer
    golden_emu.set_stackp(stack.0 as u64);
    println!(">>> Entry {:x}", entryp);
    println!(">>> Stack {:x} - {:x}", stack.0-stack_size, stack.0);

    // If we're doing proper snapshot fuzzing, set a start point.
    if DO_SNAPSHOT {
        // Pre-run the template emulator until the first `open` call
        // TODO; * manually obj-dumped for now
        let start_point = VirtAddr(0x9b19cusize);
        golden_emu.step_until(start_point).expect("Failed to pre-run the golden-emu.");
    }

    // Setting an end boundry allows gives us better perf, but possibly misses some crashes.
    if END_EARLY {
        let end_point = VirtAddr(0x185a4usize);
        golden_emu.set_end_of_fuzz_case(end_point);
    }
    
    // This mode is meant to perform basic smoke tests. It simply runs the binary once and prints
    // its exit reason to the terminal.
    if ONE_SHOT {
        println!(">>> run: {:x?}", golden_emu.run());
        println!(">>> PC : {:x?}", golden_emu.arch.get_program_counter());
        return;
    }

    ////////////////////////
    ///// Thread setup
    ////////////////////////

    // Keep track of all threads
    let mut threads = Vec::new();

    // create a stats object
    let stats      = Arc::new(Stats::default());
    let golden_emu = Arc::new(golden_emu);

    for thread_id in 0..NUM_THREADS {
        let stats = stats.clone();
        let golden_emu = golden_emu.clone();
        // Spawn a new thread
        threads.push(std::thread::spawn(move || worker(golden_emu, thread_id, stats)));
    }

    // Start a timer
    let start = Instant::now();

    let mut last_inst  = 0usize;
    let mut last_cases = 0usize;
    loop {
        let elapsed = start.elapsed().as_secs_f64();
        std::thread::sleep(Duration::from_millis(1000));
        let cases = stats.fuzz_cases.load(Ordering::SeqCst);
        let inst = stats.instructions.load(Ordering::SeqCst);
        let crashes = stats.crashes.load(Ordering::SeqCst);
        // Grab coverage information, but keep the lock length to a minimum.
        let coverage = corpus.code_coverage.len();

        let cycles        = stats.total_cycles.load(Ordering::SeqCst) as f64;
        let percent_vm    = stats.vm_cycles.load(Ordering::SeqCst) as f64 / cycles;
        let percent_mut   = stats.mut_cycles.load(Ordering::SeqCst) as f64 / cycles;
        let percent_reset = stats.reset_cycles.load(Ordering::SeqCst) as f64 / cycles;
        print!("\n[{:10.3}] Cases {:10} | FCpS {:10.0} | MIpS {:10.2} | Unique Crashes {:5}
             Reset {:10.4} | Mut  {:10.4} | VM   {:10.4} | Cov            {:5}\n", 
               elapsed, cases, cases - last_cases, (inst - last_inst) as f64 / 1000000f64, crashes,
               percent_reset, percent_mut, percent_vm, coverage);

        last_inst  = inst;
        last_cases = cases;
    }
}

fn worker(golden_emu: Arc<Emulator>, thread_id: usize, stats: Arc<Stats>) {
    // Fork our own emulator from the golden_emu
    let mut emu: Emulator = golden_emu.fork();
    // Get a new RNG instance
    let mut rng = Rng::new(thread_id as u64);
    loop {
        let mut instructions = 0usize;
        let mut crashes = 0usize;
        let mut reset_cycles = 0u64;
        let mut vm_cycles = 0u64;
        let mut mut_cycles = 0u64;
        let it0 = util::rdtsc();

        for _ in 0..BATCH_SIZE {
            let it = util::rdtsc();
            emu.randomize(&mut rng, CORRUPTION_AMOUNT);
            mut_cycles += util::rdtsc() - it;
            
            let it = util::rdtsc();
            
            let ret: (usize, VmExit);
            ret = emu.run();
            vm_cycles += util::rdtsc() - it;

            let it = util::rdtsc();
            instructions += ret.0;
            // TODO; Check for syscall not implemented
            if let Some(reason) = ret.1.is_crash() {
                crashes += crash_handler(&mut emu, &reason);
            }

            emu.reset(&golden_emu);
            reset_cycles += util::rdtsc() - it;
        }
        // Update the statistics after completing a batch
        stats.fuzz_cases.fetch_add(BATCH_SIZE, Ordering::SeqCst);
        stats.instructions.fetch_add(instructions, Ordering::SeqCst);
        stats.crashes.fetch_add(crashes, Ordering::SeqCst);

        stats.total_cycles.fetch_add(util::rdtsc() - it0, Ordering::SeqCst);
        stats.vm_cycles.fetch_add(vm_cycles, Ordering::SeqCst);
        stats.reset_cycles.fetch_add(reset_cycles, Ordering::SeqCst);
        stats.mut_cycles.fetch_add(mut_cycles, Ordering::SeqCst);
    }
}

/// Takes an emulator and generates a crash input from the current vm state.
fn crash_handler(emu: &mut Emulator, reason: &(FaultType, VirtAddrType)) -> usize {
    // Dump register state:
    let regs = emu.arch.get_register_state();
    let ip   = regs[riscv::Register::Pc as usize];

    // Get a copy of the current file
    let crash_file = emu.file_pool.dump().unwrap();

    // Determine whether this crash is "unique"
    if emu.corpus.add_crash(&crash_file, ip, reason) {
        // If so, write the crash file to disk
        let output_path = format!("./{}/crash-at-{:x}-with-{:x?}", CRASHES_DIR, ip, reason);
        fs::write(output_path, &crash_file).expect("Failed to write crash file.");
        return 1;
    }
    0
}

