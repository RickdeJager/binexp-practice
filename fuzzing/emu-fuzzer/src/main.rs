#[macro_use]
// MMU defines macro's for reading/writing integer types, so must be pulled in
// before any other modules are pulled in.
mod mmu;
mod emu;
mod riscv;
mod syscall;

use mmu::{Mmu, Perm, VirtAddr};
use mmu::{PERM_WRITE, PERM_READ, PERM_EXEC};
use emu::{Emulator, Archs};

use std::time::{Duration, Instant};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};


pub const ALLOW_GUEST_PRINT: bool = false;

const BATCH_SIZE: usize = 1000;
const NUM_THREADS: usize = 1;

#[derive(Default)]
struct Stats {
    // Total number of fuzz cases performed
    fuzz_cases: AtomicUsize,

    // Total number of crashes
    crashes: AtomicUsize
}


/// Load an elf, return the entry point on success.
fn load_elf(binary_path: &str, mmu: &mut Mmu) -> Option<u64> {
    // Read the input file from disk
    let contents = std::fs::read(binary_path).ok()?;

    let binary = goblin::elf::Elf::parse(&contents).ok()?;
    let entry = binary.entry;
    for ph in binary.program_headers {
        match ph.p_type {
            goblin::elf::program_header::PT_LOAD => {
                let virtaddr    = VirtAddr(ph.p_vaddr as usize);
                let mem_size    = ph.p_memsz  as usize;
                let file_size   = ph.p_filesz as usize;
                let file_offset = ph.p_offset as usize;
                mmu.set_permissions(virtaddr, mem_size, Perm(PERM_WRITE))?;

                // Write the file contents to memory
                mmu.write_from(virtaddr, 
                    &contents[file_offset..file_offset.checked_add(file_size)?]).ok()?;

                // Pad with zeros
                if mem_size > file_size {
                    let padding = vec![0u8; mem_size - file_size];
                    mmu.write_from( VirtAddr(virtaddr.0.checked_add(file_size)?), &padding).ok()?;
                }

                let mut permissions = Perm(0);
                // Translate Goblin perms to our custom Perms
                if ph.p_flags & goblin::elf::program_header::PF_X != 0 
                    {permissions.0 |= PERM_EXEC};
                if ph.p_flags & goblin::elf::program_header::PF_W != 0
                    {permissions.0 |= PERM_WRITE};
                if ph.p_flags & goblin::elf::program_header::PF_R != 0
                    {permissions.0 |= PERM_READ};

                // Set the permissions as specified in the Section struct.
                mmu.set_permissions(virtaddr, mem_size, permissions)?;

                // Update the allocator beyond any sections we load, to ensure this memory can't
                // be allocated again.
                mmu.cur_alloc = VirtAddr(std::cmp::max(
                        mmu.cur_alloc.0, 
                        (virtaddr.0 + mem_size + 0xf) & !0xf
                ));
            },
            _ => ()
        }
    }

    Some(entry)
}

fn main() {
    let binary_path = "./riscv/echo-argv";
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

    let argv = vec!["echo-argv", "Let's", "echo", "some", "values"];

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

    let mut golden_emu = Emulator::new(Archs::RiscV, memory.fork());

    // Set the emu's entry point
    golden_emu.set_entry(entryp);
    // Set the emu's stack pointer to point to our newly created stack pointer
    golden_emu.set_stackp(stack.0 as u64);


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
