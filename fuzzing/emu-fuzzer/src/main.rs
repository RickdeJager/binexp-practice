#[macro_use]
// MMU defines macro's for reading/writing integer types, so must be pulled in
// before any other modules are pulled in.
mod mmu;
mod emu;
mod riscv;
mod util;
mod syscall;
mod files;

use mmu::{Mmu, VirtAddr};
use emu::{Emulator, Archs};
use util::load_elf;

use std::time::{Duration, Instant};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};


pub const ALLOW_GUEST_PRINT: bool = true;

const BATCH_SIZE: usize = 1000;
const NUM_THREADS: usize = 1;

#[derive(Default)]
struct Stats {
    // Total number of fuzz cases performed
    fuzz_cases: AtomicUsize,

    // Total number of crashes
    crashes: AtomicUsize
}


fn main() {
    let binary_path = "./riscv/text-file-parser";
    let corpus_file = "./corpus/lipsum.vf";
    let mmu_size   = 1024 * 1024;
    let stack_size = 1024 * 64;
    let mut memory = Mmu::new(mmu_size);
    let entryp = load_elf(binary_path, &mut memory).expect("Failed to parse ELF.");
    // Create a stack
    let mut stack = memory.allocate(stack_size).expect("Failed to allocate stack.");

    // Set the initial stack pointer to the end of the stack.
    stack.0 += stack_size;

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
    for &item in argv.iter().rev() {
        let tmp = item.as_bytes();
        // Some functions like strlen, will batch read values, so we need to pad to the
        // next 0xf alligned string length.
        let alloc_len = (tmp.len() + 1 + 0xf) & !0xf;
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



    // Keep track of all threads
    let mut threads = Vec::new();

    // create a stats object
    let stats      = Arc::new(Stats::default());

    //TODO; WIP
    println!("{:?}", golden_emu.run());

    return;

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
        let crashes = stats.crashes.load(Ordering::SeqCst);
        print!("[{:10.3}] Cases {:10} | FCpS {:10.2} | Crashes {:10}\n", 
               elapsed, cases, cases as f64 / elapsed, crashes);
    }
}

fn worker(golden_emu: Arc<Emulator>, _thread_id: usize, stats: Arc<Stats>) {
    let mut emu: Emulator = golden_emu.fork();
    loop {
        for _ in 0..BATCH_SIZE {
            emu.run();
            emu.reset(&golden_emu);
        }
        // Update the statistics after completing a batch
        stats.fuzz_cases.fetch_add(BATCH_SIZE, Ordering::SeqCst);
    }
}
