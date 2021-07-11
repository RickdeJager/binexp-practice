/// Handles all virtual files on the system. Each Emulator will get its own dedicated FilePool
/// struct that holds files from the corpus.

use std::collections::HashMap;


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

#[derive(Clone, Debug)]
struct File {
    /// TODO; file level perms

    /// `stat` formatted file information
    stat: Stat,

    /// The actual contents of the source file.
    contents: Vec<u8>,

    /// Tweak vector. Contains all the changes we made to the current file.
    /// (assuming only bitflips for now)
    tweak: Vec<(usize, u8)>
}

impl File {
    /// Set a new tweak vector to influence this files contents.
    pub fn apply_tweak(&mut self, tweak: Vec<(usize, u8)>) {
        for &(idx, val) in &tweak {
            self.contents[idx] ^= val;
        }
        self.tweak = tweak;
    }

    pub fn remove_tweak(&mut self) {
        // Remove the tweak from the file
        for &(idx, val) in &self.tweak {
            self.contents[idx] ^= val;
        }

        // clear the tweak.
        self.tweak.clear();
    }

    /*
    /// Read a file, and take into account the active tweaks.
    /// TODO; This might very well cause a ton of allocations, need to test perf hit.
    ///       I expect it will be pretty bad though :(
    ///
    /// A much better strategy is to set/reset tweaks between fuzz cases, and edit
    /// the file buffer in-place, but these rust iterators are so fancy :P
    pub fn read(&self) -> Vec<u8> {
        if self.tweak.is_empty() {
            return self.contents.clone();
        }

        self.contents
            .iter()
            .enumerate()
            .filter_map(|(i, &x)| {
                if let Some(tweak) = self.tweak.get(&i) {
                    return match tweak.mode {
                        'd' => None,
                        // TODO; Add chars here (flatten?)
                        'a' => Some(x),
                        'f' => Some(x ^ tweak.value),
                          _ => None,
                    };
                }
                Some(x)
            })
            .collect::<Vec<u8>>()
    }
    */
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

}

impl FilePool {

    pub fn new() -> Self {
        let mut fp = FilePool{
            file_map: HashMap::new(),
            open_fds: Vec::new(),
        };
        // Add dummy Fd's for stdin / stdout / stderr
        for filename in ["STDIN", "STDOUT", "STDERR"].iter() {

            // Add empty backing files
            let file = File {
                contents: vec![0],
                tweak:    Vec::new(),
                stat:     Stat::new(),
            };
            fp.file_map.insert(filename.to_string(), file);
            fp.open(filename);
        }
        fp
    }

    /// Add a new file to this FilePool. FileName must be unique.
    /// The filepath is the "real" file path on disk, `filename` will be the
    /// name of the new virtual file.
    pub fn add(&mut self, filepath: &str, filename: &str) -> Option<()> {
        let contents = std::fs::read(filepath).ok()?;
        let mut file_stat = Stat::new();
        file_stat.st_size = contents.len() as i64;
        file_stat.st_blocks = (contents.len() as i64 + 511) / 512;
        // Set some defaults

        let file = File {
            stat    : file_stat,
            contents: contents, 
            tweak   : Vec::new(), 
        };
        self.file_map.insert(filename.to_string(), file);

        Some(())
    }

    /// Dump a file from the filePool. Intended to be used by the fuzzer to get
    /// crashing outputs. Emulators should use Fd's instead.
    pub fn dump(&self, filepath: &str) -> Option<Vec<u8>> {
        let file_ref = self.file_map.get(filepath)?;
        Some((*file_ref).clone().contents.to_vec())
    }

    pub fn apply_tweak(&mut self, filepath: &str, tweak: Vec<(usize, u8)>) -> Option<()> {
        self.file_map.get_mut(filepath)?.apply_tweak(tweak);
        Some(())
    }

    /// Remove all Fd's, and restore the underlying files.
    pub fn reset(&mut self) {
        self.open_fds.clear();
        for (_, file) in self.file_map.iter_mut() {
            file.remove_tweak();
        }
    }
    /// Assign an Fd to a file in the file pool
    pub fn open(&mut self, filepath: &str) -> Option<usize> {
        // Attempt to get the file from our file map
        match self.file_map.get(filepath) {
            Some(_) => {
                // Push an Fd into the filePool, return its index.
                self.open_fds.push(Fd{
                    filename: filepath.to_string(),
                    offset: 0,
                });
                Some(self.open_fds.len()-1)
            },
            None => None,
        }
    }

    /// Stat an Fd
    pub fn fstat(&self, fd_num: usize) ->  Option<&[u8]> {
        // No clue what this FD is, you get a None, enjoy.
        if fd_num >= self.open_fds.len() {
            return None;
        }

        // Fetch a reference to the file. (We guarantee this file exists, if it doesn't,
        // that's a bug in our emu and we should crash)
        let file = self.file_map.get(&self.open_fds[fd_num].filename)
            .expect("File management error.");

        Some(file.stat.to_raw_bytes())
    }

    /// Read from an FD
    pub fn read(&mut self, fd_num: usize, amount: usize) -> Option<&[u8]> {
        // No clue what this FD is, you get a None, enjoy.
        if fd_num >= self.open_fds.len() {
            return None;
        }

        // Fetch a reference to the file. (We guarantee this file exists, if it doesn't,
        // that's a bug in our emu and we should crash)
        let file = self.file_map.get(&self.open_fds[fd_num].filename)
            .expect("File management error.");

        let fd = &self.open_fds[fd_num];

        if fd.offset >= file.contents.len() {
            return Some(&[]);
        } else {
            let start = fd.offset;
            let end = std::cmp::min(file.contents.len() - fd.offset, amount);
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

        // Fetch a reference to the file. (We guarantee this file exists, if it doesn't,
        // that's a bug in our emu and we should crash)
        let file = self.file_map.get(&self.open_fds[fd_num].filename)
            .expect("File management error.");

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
