/// Handles all virtual files on the system. Each Emulator will get its own dedicated FilePool
/// struct that holds files from the corpus.

use std::fs;
use std::sync::Mutex;
use std::collections::HashMap;
use meowhash::MeowHasher;
use aht::Aht;
use atomicvec::AtomicVec;

use crate::Rng;
use crate::emu::{FaultType, VirtAddrType};
use crate::mmu::VirtAddr;
use crate::{TEST_FILE, SWAP_RATE};

pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;

#[derive(Default, Debug, Clone)]
struct Stat {
    st_dev      : u64,
    st_ino      : u64,
    st_mode     : u32,
    st_nlink    : u32,
    st_uid      : u32,
    st_gid      : u32,
    st_rdev     : u64,
    __pad1      : u64,
    st_size     : i64,
    st_blksize  : i32,
    __pad2      : i32,
    st_blocks   : i64,
    st_atime    : u64,
    st_atimensec: u64,
    st_mtime    : u64,
    st_mtimensec: u64,
    st_ctime    : u64,
    st_ctimensec: u64,
    
    __glibc_reserved: [i32; 2],
}

impl Stat {
    pub fn new() -> Self {
        let mut ret = Stat::default();
        ret.st_mode = 0x81a4;
        ret.st_blksize = 0x1000;
        ret.st_nlink = 0x1;
        ret.st_uid = 1000;
        ret.st_gid = 1000;

        ret
    }

    pub fn to_raw_bytes(&self) -> &[u8] {
        // Cast the stat structure to raw bytes
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of::<Self>())
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum TweakType {
    /// Do nothing
    NOP,
    /// Simple XOR with the tweaks value
    XOR,
    /// Set the value to a fixed byte
    SET1,
}

static MAGIC_LIST_1: [u8; 3] = [255u8, 127u8, 0u8];

#[derive(Clone, Debug)]
struct File {
    /// TODO; file level perms

    /// `stat` formatted file information
    stat: Stat,

    /// The actual contents of the source file.
    contents: Vec<u8>,

    /// Tweak vector. Contains all the changes we made to the current file.
    /// (assuming only bitflips for now)
    tweak: Vec<(TweakType, usize, u8)>
}

impl File {

    /// Used by the main program to randomly tweak the currently selected file.
    fn apply_random_tweak(&mut self, rng: &mut Rng, max_tweaks: usize) {
        // Prevent div by zero errors s.t. we can disable corruption by setting
        // max_tweaks to zero.
        if max_tweaks == 0 {
            return;
        }

        let file_len = self.contents.len();
        self.tweak.resize(rng.rand() % max_tweaks, (TweakType::NOP, 0, 0));

        self.tweak
            .iter_mut()
            .for_each(|(tt, idx, val)| {
                // Decide how to mutate based on RNG
                match rng.rand() % 100  {
                    // XOR
                    0..=80 => {
                        *tt  = TweakType::XOR;
                        *idx = rng.rand() % file_len;
                        if rng.rand() % 5 == 0 {
                            // Flip multiple bits
                            *val = (rng.rand() % 256) as u8;
                        } else {
                            // Flip a single bit
                            *val = 1u8 << (rng.rand() % 8) as u8;
                        }
                    },

                    // SET1
                    81..=99 => {
                        *tt  = TweakType::SET1;
                        *idx = rng.rand() % file_len;
                        *val = MAGIC_LIST_1[rng.rand() % MAGIC_LIST_1.len()];
                    },
                    x => unreachable!(x),
                }
            });
        self.apply_tweak();
    }

    /// Set a new tweak vector to influence this files contents.
    fn apply_tweak(&mut self) {
        // Grab separate references, so we don't keep `self` borrowed as mutable.
        let tweak = &mut self.tweak;
        let contents = &mut self.contents;
        tweak.iter_mut().for_each(|(tt, idx, val)| {
           match tt {
                TweakType::NOP   => {},
                TweakType::XOR   => contents[*idx] ^= *val,
                TweakType::SET1 => {
                    let tmp = contents[*idx];
                    contents[*idx] = *val;
                    *val = tmp;
                },
            }
        });
    }

    pub fn remove_tweak(&mut self) {
        // Grab separate references, so we don't keep `self` borrowed as mutable.
        let tweak = &mut self.tweak;
        let contents = &mut self.contents;
        // Remove tweaks from the file in reverse order to obtain the original file.
        tweak.iter_mut().rev().for_each(|(tt, idx, val)| {
           match tt {
                TweakType::NOP   => {},
                TweakType::XOR => contents[*idx] ^= *val,
                TweakType::SET1 => {
                    contents[*idx] = *val;
                },
            }
        });

        // clear the tweak.
        self.tweak.clear();
    }
}

/// An FD into one of the virtual files in the FilePool
#[derive(Clone)]
struct Fd {
    /// TODO; PERMS

    /// The name of the file we're pointing to.
    /// A FilePool can use this to get a ref on a file.
    filename: String,

    /// Offset into the file
    offset: usize,
}

#[derive(Clone)]
pub struct FilePool {
    /// A Hashmap of all files available within this FilePool.
    file_map: HashMap<String, File>,

    /// Vec of all currently opened FD's
    open_fds:  Vec<Fd>,

    /// The currently "selected" file, aka a file from the file map that we are mutating.
    selected: File,
}

impl FilePool {

    /// Add dummy files for STDIN/STDOUT/STDERR, Pick an initial file from the corpus,
    /// and add it to the file_pool
    pub fn new() -> Self{
        let mut ret = FilePool {
            file_map: HashMap::new(),
            open_fds: Vec::new(),
            selected: File {
                contents: Vec::new(),
                tweak:    Vec::new(),
                stat:     Stat::new(),
             },
        };

        // Add dummy Fd's for stdin / stdout / stderr
        for filename in ["STDIN", "STDOUT", "STDERR"].iter() {

            // Add empty backing files
            let file = File {
                contents: vec![0],
                tweak:    Vec::new(),
                stat:     Stat::new(),
            };
            // Insert the dummy file directly into the active file map.
            ret.file_map.insert(filename.to_string(), file);
            ret.open(filename);
            // Manually reserve an FD TODO; yuk
            ret.open_fds.push(Fd{
                filename: filename.to_string(),
                offset: 0,
            });
        }
        ret
    }

    /// Dump a file from the filePool. Intended to be used by the fuzzer to get
    /// crashing outputs. Emulators should use Fd's instead.
    pub fn dump(&self) -> Option<Vec<u8>> {
        Some(self.selected.contents.to_vec())
    }

    /// Get a reference to the (potentially modified) currently selected file.
    pub fn get_file_ref(&self) -> &[u8] {
        &self.selected.contents
    }

    /// Pick a new random file from the corpus and copy it over to the active file pool.
    /// If we "randomly" pick the same file, reset it instead.
    ///
    /// We will apply some significant bias to staying w/ the same file, as it avoids an
    /// expensive clone action.
    pub fn randomize(&mut self, rng: &mut Rng, max_tweaks: usize, corpus: &Corpus) {

        // Every one in X cases we swap files.
        // This is kinda costly, as we're doing a full copy.
        // TODO; Just cache the entire corpus in mem and never clone?
        if rng.rand() % SWAP_RATE  == 0  || self.selected.contents.is_empty() {
            // Pick a new file and copy the contents.
            let idx = rng.rand() % corpus.inputs.len();
            self.selected.contents = corpus.inputs.get(idx).unwrap().clone();
        } else {
            // Otherwise, remove the current tweak.
            self.selected.remove_tweak();
        }

        // Apply a new random tweak to the currently selected file.
        self.selected.apply_random_tweak(rng, max_tweaks);
    }

    /// Remove all open Fd's.
    pub fn reset(&mut self) {
        // Remove everything that isn't stdin/stderr/stdout
        self.open_fds.drain(3..);
    }

    /// Assign an Fd to a file in the file pool
    pub fn open(&mut self, filepath: &str) -> Option<usize> {
        if filepath == TEST_FILE {
                self.open_fds.push(Fd{
                    filename: filepath.to_string(),
                    offset: 0,
                });
            return Some(self.open_fds.len()-1);
        }
        None
   }

    /// Stat an Fd
    pub fn fstat(&self, fd_num: usize) ->  Option<&[u8]> {
        // No clue what this FD is, you get a None, enjoy.
        if fd_num >= self.open_fds.len() {
            return None;
        }

        if fd_num <= 2 {
            let file = self.file_map.get(&self.open_fds[fd_num].filename)
                .expect("File management error.");
            return Some(file.stat.to_raw_bytes())
        }

        // For now, just assume we statted the selected file.
        Some(self.selected.stat.to_raw_bytes())
    }

    /// Read from an FD
    pub fn read(&mut self, fd_num: usize, amount: usize) -> Option<&[u8]> {
        // No clue what this FD is, you get a None, enjoy.
        if fd_num >= self.open_fds.len() {
            return None;
        }

        if fd_num <= 2 {
            println!("[warn] read a special file (fd: {})", fd_num);
            return None;
        }

        let fd = &self.open_fds[fd_num];
        let file = &self.selected;

        if fd.offset >= file.contents.len() {
            return Some(&[]);
        } else {
            let start = fd.offset;
            let end = start + std::cmp::min(file.contents.len() - fd.offset, amount);
            // Move the FD forward
            self.open_fds[fd_num].offset = end;
            return Some(&file.contents[start..end]);
        }
    }

    /// lseek an FD
    pub fn lseek(&mut self, fd_num: usize, offset: i64, whence: i32) -> Option<i64> {
        // No clue what this FD is, you get a None, enjoy.
        if fd_num >= self.open_fds.len() {
            return None;
        }

        if fd_num <= 2 {
            unimplemented!("read a special file");
        }
        let file = &self.selected;

        match whence {
            SEEK_SET => {
                // TODO; This is not accurate, must rewrite Fds a little to allow for negative
                // file offsets.
                self.open_fds[fd_num].offset = std::cmp::max(0, offset) as usize;
                Some(offset)
            },
            SEEK_CUR => {
                self.open_fds[fd_num].offset = 
                    (self.open_fds[fd_num].offset as i64 + offset) as usize;
                Some(self.open_fds[fd_num].offset as i64)
            },
            SEEK_END => {
                self.open_fds[fd_num].offset = (file.contents.len() as i64 + offset) as usize;
                Some(self.open_fds[fd_num].offset as i64)
            },

            _ => Some(-1),
        }
    }
}


/// Populates and handles corpus data.
pub struct Corpus {

    /// A Simple hashset to dedupe the inputs
    input_hashes: Aht<u128, (), 1048576>,

    /// Vector containing all inputs as vec's of u8's
    pub inputs: AtomicVec<Vec<u8>, 1048576>,

    /// A Simple hashset to dedupe crashes. This is not based on the actual contents,
    /// but rather on the crashes' metadata like, program counter, crash type, ...
    crash_hashes: Aht<(VirtAddr, FaultType, VirtAddrType), (), 1048576>,

    /// Vector containing all unique crashes
    pub crashes: Mutex<Vec<Vec<u8>>>,

    /// A set off all PC's that can were covered by the current corpus
    pub code_coverage: Aht<VirtAddr, (), 1048576>,

}

impl Corpus {
    /// Populate the corpus from a specified directory.
    pub fn new(corpus_dir: &str) -> Option<Self> {
        let corpus = Corpus{
            input_hashes : Aht::new(),
            inputs       : AtomicVec::new(),
            crash_hashes : Aht::new(),
            crashes      : Mutex::new(Vec::new()),
            code_coverage: Aht::new(),
        };

        // Load the initial corpus by grabbing all files in the directory.
        for file_name in fs::read_dir(corpus_dir).ok()? {
            let contents = std::fs::read(file_name.unwrap().path()).ok()?;
            corpus.add_input(&contents);
        }
        Some(corpus)
    }

    /// Add a new file to the Corpus, given its contents as a u8 vec.
    pub fn add_input(&self, contents: &[u8]) -> bool {
        let mut ret = false;
        // Use a fast non-cryptographically secure hash for dedupe.
        let hash = MeowHasher::hash(contents).as_u128();
        self.input_hashes.entry_or_insert(&hash, hash as usize, || {
            // Insert to files vec if the hash wasn't present yet.
            self.inputs.push(Box::new(contents.to_vec()));
            ret = true;
            Box::new(())
        });
        ret
    }

    /// Add a crashing input to both the input set we are pulling from, as well
    /// as the crash set we'll be saving to disk.
    pub fn add_crash(&self, contents: &[u8], ip: u64, reason: &(FaultType, VirtAddrType))
        -> bool {

        let ip = ip as usize;
        let mut ret = false;
        self.crash_hashes.entry_or_insert(&(VirtAddr(ip), reason.0, reason.1), ip, || {
            // Insert to files vec if the hash wasn't present yet.
            // TODO; This should ideally also be using an atomic vec, but this case is fairly rare,
            // so this is fine for now.
            {
                let mut crashes = self.crashes.lock().unwrap();
                crashes.push(contents.to_vec());
            }

            // Also add the crash to our input set.
            self.add_input(contents);

            ret = true;
            Box::new(())
        });
        ret
    }
}

