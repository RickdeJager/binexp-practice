pub const PERM_READ : u8 = 1 << 0;
pub const PERM_WRITE: u8 = 1 << 1;
pub const PERM_EXEC : u8 = 1 << 2;
// Read after write
pub const PERM_RAW  : u8 = 1 << 3;

/// Block size used to track dirty blocks of memory. This value can be tweaked to optimise
/// perf for your specific target.
/// Setting this to a larger value causes fewer, large memcpy's to occur, setting
/// this to a lower value causes more, smaller memcpy's to occur.
const DIRTY_BLOCK_SIZE: usize = 4096;

/// Permission flags to track the state of bytes in memory.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Perm(pub u8);

/// A guest virtual address
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct VirtAddr(pub usize);

/// The memory space for a single emu
pub struct Mmu {
    /// Block of memory for this address space
    /// Offset 0 will correspond to offset 0 in the guests address space.
    memory: Vec<u8>,

    /// Permission bytes for the corresponding byte in `memory`
    permissions: Vec<Perm>,

    /// Tracks blocks indices of memory that are dirty.
    dirty: Vec<usize>,

    /// Tracks which parts of memory have been dirtied.
    dirty_bitmap: Vec<u64>,

    /// Current base address of the next allocation to perform
    pub cur_alloc: VirtAddr,
}

impl Mmu {
    /// Create a new memory space of size `size`
    pub fn new(size: usize) -> Self {
        Mmu {
            memory      : vec![0; size],
            permissions : vec![Perm(0); size],
            dirty       : Vec::with_capacity(size / DIRTY_BLOCK_SIZE + 1),
            dirty_bitmap: vec![0u64; size / DIRTY_BLOCK_SIZE / 64 + 1],
            cur_alloc   : VirtAddr(0x10000),
        }
    }

    // Fork from an existing Mmu
    pub fn fork(&self) -> Self {
        let size = self.memory.len();

        Mmu {
            memory      : self.memory.clone(),
            permissions : self.permissions.clone(),
            // Keep the dirty bits clear.                          
            dirty       : Vec::with_capacity(size / DIRTY_BLOCK_SIZE + 1),
            dirty_bitmap: vec![0u64; size / DIRTY_BLOCK_SIZE / 64 + 1],
            cur_alloc   : self.cur_alloc.clone(),
        }
    }

    /// Restore the Mmu's memory to some original state. This will take all dirty blocks
    /// in `self`, and replace them by the contents in the provided state.
    pub fn reset(&mut self, other: &Mmu) {
        for &block in &self.dirty {
            let start =  block * DIRTY_BLOCK_SIZE;
            let end   = (block + 1) * DIRTY_BLOCK_SIZE;

            // Zero out the bitmap
            self.dirty_bitmap[block / 64] = 0;

            // Restore the memory and permissions
            self.memory[start..end].copy_from_slice(&other.memory[start..end]);
            self.permissions[start..end].copy_from_slice(&other.permissions[start..end]);
        }

        // Clear the old dirty list
        self.dirty.clear();
    }

    /// Allocate a region of memory as RW.
    pub fn allocate(&mut self, size: usize) -> Option<VirtAddr> {

        // 16-byte align the allocation
        let aligned_size = (size + 0xf) & !0xf;

        // Get the current allocation base
        let base = self.cur_alloc;

        // We can't allocate if base exceeds memory length
        if base.0 >= self.memory.len() {
            return None;
        }

        // Update the allocation size (check for overflow)
        self.cur_alloc = VirtAddr(self.cur_alloc.0.checked_add(aligned_size)?);

        // Allocation would go out of memory, failed to alloc
        if self.cur_alloc.0 > self.memory.len() {
            return None;
        }

        // Mark the new memory as uninitialized and writable.
        self.set_permissions(base, size, Perm(PERM_RAW | PERM_WRITE));

        Some(base)
    }

    /// Apply permissions to a region of memory, denoted by offset, len
    pub fn set_permissions(&mut self, addr: VirtAddr, size: usize, perm: Perm) -> Option<()> {
        // Iter over the permission bits and apply permissions
        self.permissions
            .get_mut(addr.0..addr.0.checked_add(size)?)?
            .iter_mut()
            .for_each(|x| *x = perm);
        Some(())
    }

    /// Write bytes from `buf` into `addr`
    pub fn write_from(&mut self, addr: VirtAddr, buf: &[u8]) -> Option<()> {
    
        // First, check the permissions bits
        let mut has_raw = false;
        // Get a mutable ref to permissions so we can update them
        let perms = self.permissions.get_mut(addr.0..addr.0.checked_add(buf.len())?)?;

        if !perms.iter().all(|x| {
            // Check if we pass any RAW bits along the way.
            has_raw |= (x.0 & PERM_RAW) != 0;
            // Do the actual write perm check
            (x.0 & PERM_WRITE) != 0
        }) { 
            // Failed to write because at least on byte was missing write perms
            return None;
        }

        // Do the actual write operation
        self.memory
            .get_mut(addr.0..addr.0.checked_add(buf.len())?)?
            .copy_from_slice(buf);

        // Mark dirty blocks
        let block_start = addr.0 / DIRTY_BLOCK_SIZE;
        let block_end   = (addr.0 + buf.len()) / DIRTY_BLOCK_SIZE;

        for block in block_start..=block_end {
            // Determine the bitmap position of the dirty block
            let idx = block_start / 64;
            let bit = block_start % 64;

            // Check if the block is not dirty
            if self.dirty_bitmap[idx] & (1 << bit) == 0 {
                // Block is not dirty yet, add it to the dirty list.
                self.dirty.push(block);

                // Update the dirty bitmap
                self.dirty_bitmap[idx] |= 1 << bit;
            }
        }

        // If any bytes had the RAW bit set, mark everything we just wrote to as readable.
        if has_raw {
            perms
                .iter_mut()
                .filter(|x| (x.0 & PERM_RAW) != 0)
                .for_each(|x| {*x = Perm(x.0 | PERM_READ)});
        }


        Some(())
    }

    /// Write bytes from `buf` into `addr`
    pub fn read_into(&self, addr: VirtAddr, buf: &mut [u8]) -> Option<()> {

        let perms = self.permissions.get(addr.0..addr.0.checked_add(buf.len())?)?;

        // If we attempt to read a non-readable byte, return an error.
        if perms.iter().any(|x| x.0 & PERM_READ == 0) {
            return None;
        }

        // Otherwise, attempt the read.
        buf.copy_from_slice(
            self.memory.get(addr.0..addr.0.checked_add(buf.len())?)?
        );

        Some(())
    }
}


