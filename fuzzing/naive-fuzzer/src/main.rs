use std::io;
use std::fs;
use std::time::{Duration, Instant};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::path::Path;
use std::collections::BTreeSet;
use std::process::{Command, ExitStatus};
use std::os::unix::process::ExitStatusExt;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hasher, Hash};

const BINARY_PATH: &str = "../../vulnerable_programs/text_file_parser/vuln";
const CORPUS_DIR:  &str = "./corpus";
const CRASHES_DIR: &str = "./crashes";
const INPUT_DIR: &str = "./tempinputs";

/// Number of iterations to run per thread, before collecting stats.
const BATCH_SIZE: usize = 700;

/// Corpus type: A vector of byte vectors
type Corpus = Vec<Vec<u8>>;

#[derive(Default)]
struct Statistics {
    // Total number of fuzz cases performed
    fuzz_cases: AtomicUsize,

    // Total number of crashes
    crashes: AtomicUsize
}

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


/// Save `inp` to disk, using a unique file name, based on the provided thread id.
/// Afterwards, pass it to our target binary
fn fuzz<P: AsRef<Path>>(file_name: P, inp: &[u8]) -> io::Result<ExitStatus> {
    // Write the input to a temp file
    // (unwrap to bubble up any errors)
    fs::write(file_name.as_ref(), inp)?;

    let runner = Command::new(BINARY_PATH).args(&[
        file_name.as_ref().to_str().unwrap()
    ]).output()?;

    Ok(runner.status)
}

/// A worker thread that keeps fuzzing for ever and ever.
fn worker(thread_id: usize, statistics: Arc<Statistics>, corpus: Arc<Corpus>) -> io::Result<()> {

    // Compute the filname once
    let file_name = format!("{}/tempinput-{}", INPUT_DIR, thread_id);

    // Get a new RNG instance
    let mut rng = Rng::new(thread_id as u64);

    // Alloc the input for the fuzz case once
    let mut fuzz_input = Vec::new();

    // Get a hash object to name crashes with
    let mut hasher = DefaultHasher::new();

    loop {
        for _ in 0..BATCH_SIZE {

            // Pick a random input "file" from the corpus
            let sel = rng.rand() % corpus.len();

            // Set up the new fuzz input, but reuse the old allocation
            fuzz_input.clear();
            fuzz_input.extend_from_slice(&corpus[sel]);

            // Flip some bitties
            for _ in 0..rng.rand() % 8 {
                fuzz_input[rng.rand() % &corpus[sel].len()] 
                    ^= (rng.rand() % 255) as u8;
            }

            let exit_sig = fuzz(&file_name, &fuzz_input)?.signal();
            match exit_sig {
                //SEGFAULT
                Some(11) => {
                    // Add to the stats
                    statistics.crashes.fetch_add(1, Ordering::SeqCst);

                    // Write the crash file
                    fuzz_input.hash(&mut hasher);
                    let file_name = hasher.finish();
                    let output_path = format!("./{}/crash-{}", CRASHES_DIR, file_name);
                    fs::write(output_path, &fuzz_input)?;
                },
                       _ => ()
            }
        }

        // Update the statistics after completing a batch
        statistics.fuzz_cases.fetch_add(BATCH_SIZE, Ordering::SeqCst);
    }
}


fn main() -> io::Result<()> {

    // Load the initial corpus
    let mut corpus = BTreeSet::new();
    for file_name in fs::read_dir(CORPUS_DIR)? {
        let file_name = file_name?.path();
        corpus.insert(fs::read(file_name)?);
    }

    // Turn the corpus into an Arc obj
    let corpus: Arc<Corpus> = Arc::new(corpus.into_iter().collect());

    // Keep track of all threads
    let mut threads = Vec::new();

    // create a stats object
    let stats = Arc::new(Statistics::default());

    for thread_id in 0..6 {
        let stats = stats.clone();
        let corpus = corpus.clone();
        // Spawn a new thread
        threads.push(std::thread::spawn(move || worker(thread_id, stats, corpus)));
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
