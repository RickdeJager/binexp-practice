#[macro_use]
// MMU defines macro's for reading/writing integer types, so must be pulled in
// before any other modules are pulled in.
mod mmu;
mod emu;
mod riscv;
mod util;
mod syscall;
mod files;
mod ui;

use std::fs;
use mmu::{Mmu, VirtAddr};
use emu::{Emulator, Archs, VmExit};
use util::load_elf;

use std::time::{Duration, Instant};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

pub const ALLOW_GUEST_PRINT: bool = false;
pub const ONE_SHOT: bool = false;
pub const FLASHY: bool = false;

pub const CRASHES_DIR: &str = "./crashes";
pub const CORPUS_DIR : &str = "./corpus";
pub const TEST_FILE : &str = "testfile";

const BATCH_SIZE: usize = 400;
const NUM_THREADS: usize = 8;


struct Rng(u64);

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
    // Total number of fuzz cases performed
    fuzz_cases: AtomicUsize,

    // Total number of crashes
    crashes: AtomicUsize,

    // Total number of instructions executed
    instructions: AtomicUsize,
}

fn main() {
    let binary_path = "./riscv/text-file-parser";
    let corpus_file = "./corpus/lipsum.vf";
    let mmu_size   = 1024 * 1024;
    let stack_size = 1024 * 512;
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

    let argv = vec![binary_path, TEST_FILE];

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
    let file_pool = files::FilePool::new_file(corpus_file);
//    file_pool.add(corpus_file).expect("Failed to load real file from disk.");
    let mut golden_emu = Emulator::new(Archs::RiscV, memory, file_pool);

    // Set the emu's entry point
    golden_emu.set_entry(entryp);
    // Set the emu's stack pointer to point to our newly created stack pointer
    golden_emu.set_stackp(stack.0 as u64);
    println!(">>> Stack {:x} - {:x}", stack.0-stack_size, stack.0);

    
    if ONE_SHOT {
        println!(">>> run: {:x?}", golden_emu.run());
        return;
    }

    // Pre-run the template emulator until the first `open` call
    // TODO; * manually obj-dumped for now
  //  golden_emu.run_until(0x28e58).expect("Failed to pre-run the golden-emu.");

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


    if FLASHY {
        let mut ui = ui::Ui::new(stats.clone()).expect("Failed to create UI.");
        loop {
            ui.tick(start.elapsed());
            std::thread::sleep(Duration::from_millis(100));
        }
    } else {
        let mut last_inst  = 0usize;
        let mut last_cases = 0usize;
        loop {
            let elapsed = start.elapsed().as_secs_f64();
            std::thread::sleep(Duration::from_millis(1000));
            let cases = stats.fuzz_cases.load(Ordering::SeqCst);
            let inst = stats.instructions.load(Ordering::SeqCst);
            let crashes = stats.crashes.load(Ordering::SeqCst);
            print!("[{:10.3}] Cases {:10} | FCpS {:10.0} | MIpS {:10.3} | Crashes {:5}\n", 
                   elapsed, cases, cases - last_cases, (inst - last_inst) as f64 / 1000000f64, 
                   crashes);

            last_inst  = inst;
            last_cases = cases;
        }
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
        for _ in 0..BATCH_SIZE {
            emu.arch.apply_tweak(TEST_FILE, get_random_tweak(&mut rng, 3));
            let ret = emu.run();

            instructions += ret.0;
            if !matches!(ret.1, VmExit::Exit(_)) {
                crashes += 1;
                crash_handler(&emu, &ret.1);
            }

            emu.reset(&golden_emu);
        }
        // Update the statistics after completing a batch
        stats.fuzz_cases.fetch_add(BATCH_SIZE, Ordering::SeqCst);
        stats.instructions.fetch_add(instructions, Ordering::SeqCst);
        stats.crashes.fetch_add(crashes, Ordering::SeqCst);
    }
}

fn get_random_tweak(rng: &mut Rng, max_len: usize) -> Vec<(usize, u8)> {
    let mut tweak = vec![(0usize, 0u8); rng.rand() % 8];
    tweak
        .iter_mut()
        .for_each(|(idx, val)| {
            *idx = rng.rand() % max_len;
            *val = (rng.rand() % 256) as u8;
        });
    tweak
}

/// Takes an emulator and generates a crash input from the current vm state.
fn crash_handler(emu: &Emulator, exit: &VmExit) {
    // Dump register state:
    let regs = emu.arch.get_register_state();

    // Get a copy of the current file
    let crash_file = emu.arch.get_filepool_ref().dump(TEST_FILE).unwrap();

    // Write the crash file
    // TODO; Check if the output path already exists before blindly writing to disk.
    let output_path = format!("./{}/crash-at-{:x}-with-{:x?}", 
                              CRASHES_DIR, regs[riscv::Register::Pc as usize], exit);
    fs::write(output_path, &crash_file).expect("Failed to write crash file.");
}
