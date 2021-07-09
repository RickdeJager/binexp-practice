use crate::emu::VmExit;

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

/// Small little helper macro to get type lengths at compile time
macro_rules! get_type_len {
    (u8)   => {1};
    (u16)  => {2};
    (u32)  => {4};
    (u64)  => {8};
    (u128) => {16};
    (i8)   => {1};
    (i16)  => {2};
    (i32)  => {4};
    (i64)  => {8};
    (i128) => {16};
}

/// Macro to read a value from memory while honouring the perms
macro_rules! mmu_read_perms {
    ($mmu: expr, $addr: expr, $perms: expr, $type: tt) => {
        {
            let mut tmp = [0u8; get_type_len!($type)];
            $mmu.read_into_perms($addr, &mut tmp, $perms)?;
            Ok(<$type>::from_le_bytes(tmp))
        }
    };
}

/// Macro to read a value from memory with PERM_READ
macro_rules! mmu_read {
    ($mmu: expr, $addr: expr, $type: tt) => {
        {
            let mut tmp = [0u8; get_type_len!($type)];
            $mmu.read_into_perms($addr, &mut tmp, Perm(PERM_READ))?;
            Ok(<$type>::from_le_bytes(tmp))
        }
    };
}

/// Macro to write a value to memory
macro_rules! mmu_write {
    ($mmu: expr, $addr: expr, $value: expr) => {
        {
            let tmp = $value.to_le_bytes();
            $mmu.write_from($addr, &tmp)
        }
    };
}

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

    /// The lowest address in the allocated stack.
    pub stack_location: VirtAddr,
}

impl Mmu {
    /// Create a new memory space of size `size`
    pub fn new(size: usize) -> Self {
        Mmu {
            memory        : vec![0; size],
            permissions   : vec![Perm(0); size],
            dirty         : Vec::with_capacity(size / DIRTY_BLOCK_SIZE + 1),
            dirty_bitmap  : vec![0u64; size / DIRTY_BLOCK_SIZE / 64 + 1],
            cur_alloc     : VirtAddr(0x10000),
            stack_location: VirtAddr(0),
        }
    }

    // Fork from an existing Mmu
    pub fn fork(&self) -> Self {
        let size = self.memory.len();

        Mmu {
            memory        : self.memory.clone(),
            permissions   : self.permissions.clone(),
            // Keep the dirty bits clear.                          
            dirty         : Vec::with_capacity(size / DIRTY_BLOCK_SIZE + 1),
            dirty_bitmap  : vec![0u64; size / DIRTY_BLOCK_SIZE / 64 + 1],
            cur_alloc     : self.cur_alloc.clone(),
            stack_location: self.stack_location.clone(),
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

            // Restore allocator state
            self.cur_alloc = other.cur_alloc;
        }

        // Clear the old dirty list
        self.dirty.clear();
    }

    /// Allocate a region of memory as RW.
    pub fn allocate(&mut self, size: usize) -> Option<VirtAddr> {

        // Get the current allocation base
        let base = self.cur_alloc;

/*        // We can't allocate if base exceeds the stack
        if base.0 >= self.memory.len() {
            return None;
        }*/

        // Update the allocation size (check for overflow)
        self.cur_alloc = VirtAddr(self.cur_alloc.0.checked_add(size)?);

        // Allocation would go out of memory, failed to alloc
        if self.cur_alloc.0 > self.stack_location.0 {
            return None;
        }

        // Mark the new memory as uninitialized and writable.
        self.set_permissions(base, size, Perm(PERM_RAW | PERM_WRITE));

        Some(base)
    }

    /// Manually allocate a stack at the end of the memory block
    /// Returns a pointer to the end of the newly allocated stack.
    pub fn allocate_stack(&mut self, size: usize) -> Option<VirtAddr> {
        // Make sure the stack fits
        if self.cur_alloc.0.checked_add(size)? > self.memory.len() {
            return None;
        }

        let base = VirtAddr(self.memory.len() - size);

        // Mark the new memory as uninitialized and writable.
        self.set_permissions(base, size, Perm(PERM_RAW | PERM_WRITE));

        // Save the bottom of the stack
        self.stack_location = base;

        Some(VirtAddr(base.0 + size))
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
    pub fn write_from(&mut self, addr: VirtAddr, buf: &[u8]) -> Result<(), VmExit> {
    
        // First, check the permissions bits
        let mut has_raw = false;
        // Get a mutable ref to permissions so we can update them
        let perms = self.permissions.get_mut(addr.0..addr.0.checked_add(buf.len())
                    .ok_or(VmExit::AddressIntegerOverflow)?)
                    .ok_or(VmExit::AddressMiss(addr, buf.len()))?;

        if !perms.iter().all(|x| {
            // Check if we pass any RAW bits along the way.
            has_raw |= (x.0 & PERM_RAW) != 0;
            // Do the actual write perm check
            (x.0 & PERM_WRITE) != 0
        }) { 
            // Failed to write because at least on byte was missing write perms
            return Err(VmExit::WriteFault(addr, buf.len()));
        }

        // Do the actual write operation
        self.memory
            .get_mut(addr.0..addr.0.checked_add(buf.len())
                    .ok_or(VmExit::AddressIntegerOverflow)?)
                    .ok_or(VmExit::AddressMiss(addr, buf.len()))?
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
        Ok(())
    }

    /// Write bytes from `buf` into `addr`
    pub fn read_into(&self, addr: VirtAddr, buf: &mut [u8]) -> Result<(), VmExit> {
        self.read_into_perms(addr, buf, Perm(PERM_READ))
    }

    /// Write bytes from `buf` into `addr` and apply special permissions
    pub fn read_into_perms(&self, addr: VirtAddr, buf: &mut [u8], perm: Perm) 
            -> Result<(), VmExit> {

        let perms = self.permissions.get(addr.0..addr.0.checked_add(buf.len())
                    .ok_or(VmExit::AddressIntegerOverflow)?)
                    .ok_or(VmExit::AddressMiss(addr, buf.len()))?;

        // If we attempt to read a byte that lacks some of the required permissions,
        // return an error.
        if perms.iter().any(|x| (x.0 & perm.0) != perm.0) {
            return Err(VmExit::ReadFault(addr, buf.len()));
        }

        // Otherwise, attempt the read.
        buf.copy_from_slice(
            self.memory.get(addr.0..addr.0.checked_add(buf.len())
                    .ok_or(VmExit::AddressIntegerOverflow)?)
                    .ok_or(VmExit::AddressMiss(addr, buf.len()))?
        );
        Ok(())
    }
}

