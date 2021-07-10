#[macro_use]
// MMU defines macro's for reading/writing integer types, so must be pulled in
// before any other modules are pulled in.
mod mmu;
mod emu;
mod riscv;
mod util;
mod syscall;
mod files;

use std::fs;
use mmu::{Mmu, VirtAddr};
use emu::{Emulator, Archs, VmExit};
use util::load_elf;

use std::time::{Duration, Instant};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};


pub const ALLOW_GUEST_PRINT: bool = false;
pub const CRASHES_DIR: &str = "./crashes";

const BATCH_SIZE: usize = 10;
const NUM_THREADS: usize = 1;

#[derive(Default)]
struct Stats {
    // Total number of fuzz cases performed
    fuzz_cases: AtomicUsize,

    // Total number of crashes
    crashes: AtomicUsize,

    // Total number of instructions executed
    instructions: AtomicUsize,
}


fn main() {
    let binary_path = "./riscv/text-file-parser";
    let corpus_file = "./corpus/crash.vf";
    let mmu_size   = 1024 * 1024;
    let stack_size = 1024 * 32;
    let mut memory = Mmu::new(mmu_size);
    let entryp = load_elf(binary_path, &mut memory).expect("Failed to parse ELF.");
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

    let argv = vec![binary_path, "testfile"];

    push_i!(0u64); // AUXP
    push_i!(0u64); // ENVP
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

    // Add a files to the filePool
    let mut file_pool = files::FilePool::new();
    file_pool.add(corpus_file, "testfile");
    let mut golden_emu = Emulator::new(Archs::RiscV, memory, file_pool);

    // Set the emu's entry point
    golden_emu.set_entry(entryp);
    // Set the emu's stack pointer to point to our newly created stack pointer
    golden_emu.set_stackp(stack.0 as u64);

    println!(">>> Stack {:x} - {:x}", stack.0-stack_size, stack.0);
    
    /*
    println!(">>> run: {:x?}", golden_emu.run());
    return;*/

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

    loop {
        std::thread::sleep(Duration::from_millis(1000));

        let elapsed = start.elapsed().as_secs_f64();
        let cases = stats.fuzz_cases.load(Ordering::SeqCst);
        let inst = stats.instructions.load(Ordering::SeqCst);
        let crashes = stats.crashes.load(Ordering::SeqCst);
        print!("[{:10.3}] Cases {:10} | FCpS {:10.0} | MIpS {:10.3} | Crashes {:10}\n", 
               elapsed, cases, cases as f64 / elapsed, inst as f64 / 1000000f64 / elapsed, crashes);
    }
}

fn worker(golden_emu: Arc<Emulator>, _thread_id: usize, stats: Arc<Stats>) {
    let mut emu: Emulator = golden_emu.fork();
    loop {
        let mut instructions = 0usize;
        let mut crashes = 0usize;
        for _ in 0..BATCH_SIZE {
            let ret = emu.run();
            instructions += ret.0;
            if !matches!(ret.1, VmExit::Exit(0)) {
                crashes += 1;
                crash_handler(&emu);
            }
            emu.reset(&golden_emu);
        }
        // Update the statistics after completing a batch
        stats.fuzz_cases.fetch_add(BATCH_SIZE, Ordering::SeqCst);
        stats.instructions.fetch_add(instructions, Ordering::SeqCst);
        stats.crashes.fetch_add(crashes, Ordering::SeqCst);
    }
}


/// Takes an emulator and generates a crash input from the current vm state.
fn crash_handler(emu: &Emulator) {
    // Dump register state:
    let regs = emu.arch.get_register_state();

    // Get a copy of the current file
    let crash_file = emu.arch.get_filepool_ref().dump("testfile").unwrap();

    // Write the crash file
    // TODO; Check if the output path already exists before blindly writing to disk.
    let output_path = format!("./{}/crash-at-{:x}", CRASHES_DIR, regs[riscv::Register::Pc as usize]);
    fs::write(output_path, &crash_file).expect("Failed to write crash file.");
}
