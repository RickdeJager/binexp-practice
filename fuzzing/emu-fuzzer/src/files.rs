/// Handles all virtual files on the system. Each Emulator will get its own dedicated FilePool
/// struct that holds files from the corpus.

use std::collections::HashMap;


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
    pub fn to_raw_bytes(&self) -> &[u8] {
        // Cast the stat structure to raw bytes
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of_val(&self))
        }
    }
}

#[derive(Clone)]
struct File {
    /// TODO; file level perms

    /// `stat` formatted file information
    stat: Stat,

    /// The actual contents of the file.
    contents: Vec<u8>,
}

/// An FD into one of the virtual files in the FilePool
#[derive(Clone)]
struct Fd {

    /// TODO; PERMS

    /// The actual file we're pointing to
    file: File,

    /// Offset into the file
    offset: usize,

}

#[derive(Clone)]
pub struct FilePool {
    /// A Hashmap of all files available within this FilePool.
    file_map: HashMap<String, File>,

    /// Vec of all currently opened FD's
    open_fds: Vec<Fd>,

}

impl FilePool {

    pub fn new() -> Self {
        FilePool{
            file_map: HashMap::new(),
            open_fds: Vec::new(),
        }
        // TODO; Create FD's for stdin/stdout/stderr here, so we can fstat them.
    }

    /// Add a new file to this FilePool. FileName must be unique.
    /// The filepath is the "real" file path on disk, `filename` will be the
    /// name of the new virtual file.
    pub fn add(&mut self, filepath: &str, filename: &str) -> Option<()> {
        let contents = std::fs::read(filepath).ok()?;
        let mut file_stat = Stat::default();
        file_stat.st_size = contents.len() as i64;
        let file = File {
            stat    : file_stat,
            contents: contents, 
        };
        self.file_map.insert(filename.to_string(), file);

        Some(())
    }

}
