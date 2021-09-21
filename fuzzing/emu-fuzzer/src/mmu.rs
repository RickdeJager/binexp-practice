use crate::emu::VmExit;
use std::collections::BTreeMap;

pub const PERM_READ : u8 = 1 << 0;
pub const PERM_WRITE: u8 = 1 << 1;
pub const PERM_EXEC : u8 = 1 << 2;
// Read after write
pub const PERM_RAW  : u8 = 1 << 3;

/// Block size used to track dirty blocks of memory. This value can be tweaked to optimise
/// perf for your specific target.
/// Setting this to a larger value causes fewer, large memcpy's to occur, setting
/// this to a lower value causes more, smaller memcpy's to occur.
/// (For JIT reasons, this is required to be a power of 2, and greater than 8)
pub const DIRTY_BLOCK_SIZE: usize = 0x80;

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

    /// A map that contains every address we've returned from malloc, along with the
    /// allcocation size.
    pub malloc_map: BTreeMap<VirtAddr, usize>,
}

impl Mmu {
    /// Create a new memory space of size `size`
    pub fn new(size: usize) -> Self {

        // In our JIT, we make some assumptions on the dirty block size. To keep things simple,
        // we'll just make this a general requirement, even if running in interpreted mode.
        assert!(DIRTY_BLOCK_SIZE.count_ones() == 1 && DIRTY_BLOCK_SIZE >= 8,
                "Dirty block size must be a power of two and >= 8");

        Mmu {
            memory        : vec![0; size],
            permissions   : vec![Perm(0); size],
            dirty         : Vec::with_capacity(size / DIRTY_BLOCK_SIZE + 1),
            dirty_bitmap  : vec![0u64; size / DIRTY_BLOCK_SIZE / 64 + 1],
            cur_alloc     : VirtAddr(0x10000),
            stack_location: VirtAddr(0),
            malloc_map    : BTreeMap::new(),
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
            malloc_map    : self.malloc_map.clone(),
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

        // Clear the malloc_set
        self.malloc_map.clear();
        // Copy the malloc_set from the other memory state over.
        self.malloc_map.extend(&other.malloc_map);

        // Assert that the mmu's are identical after reset.
        if crate::DEBUG_MODE {
            assert!(self.cur_alloc == other.cur_alloc);
            assert!(self.memory == other.memory);
            assert!(self.permissions == other.permissions);
            assert!(self.malloc_map == other.malloc_map);

        }
    }

    /// Getter function to get all pointers required to run the JIT:
    /// - memory pointer
    /// - permissions pointer
    /// - dirty pointer
    /// - dirty bitmap pointer
    #[inline]
    pub fn jit_addresses(&self) -> (usize, usize, usize, usize) {
        (
            self.memory.as_ptr() as usize,
            self.permissions.as_ptr() as usize,
            self.dirty.as_ptr() as usize,
            self.dirty_bitmap.as_ptr() as usize,
        )
    }

    /// Get the dirty list length
    #[inline]
    pub fn dirty_len(&self) -> usize {
        self.dirty.len()
    }

    /// Set the dirty list length.
    /// Used to forcefully update the vec size, after we added some data to the backing store
    /// from within the JIT. This is only allowed because we reserved enough space in the vector
    /// to hold all possible dirty blocks, otherwise this would go OOB.
    #[inline]
    pub unsafe fn set_dirty_len(&mut self, len: usize) {
        self.dirty.set_len(len);
    }

    /// Get the length of the memory vec.
    #[inline]
    pub fn mem_len(&self) -> usize {
        self.memory.len()
    }

    /// Allocate a region of memory as RW.
    pub fn allocate(&mut self, size: usize) -> Option<VirtAddr> {
        // Mark the new memory as uninitialized and writable by default.
        let perms = match crate::ENABLE_RAW_PERM {
            false => Perm(PERM_READ | PERM_WRITE),
            true  => Perm(PERM_RAW | PERM_WRITE),
        };
        self.allocate_perms(size, perms)
    }

    /// Allocate with non-standard permissions
    pub fn allocate_perms(&mut self, size: usize, perm: Perm) -> Option<VirtAddr> {
        // Add some padding and alignment iff we're running a stricter allocator
        let align_size = match crate::HOOK_ALLOCATIONS {
            true  => (size + 0x1f) & !0xf,
            false =>  size,
        };

        // Get the current allocation base
        let base = self.cur_alloc;

        // If alloc is called on null, just return the current base right away.
        if size == 0 {
            return Some(base);
        }

        // Update the allocation size (check for overflow)
        let new_base = VirtAddr(self.cur_alloc.0.checked_add(align_size)?);

        // Allocation would go out of memory, failed to alloc
        if new_base.0 >= self.stack_location.0 {
            return None;
        }

        // Apply the new base in case the allocation succeeds.
        self.cur_alloc = new_base;

        // Apply permissions to the newly allocated memory
        self.set_permissions(base, size, perm);
        Some(base)
    }

    /// Manually allocate a stack at the end of the memory block
    /// Returns a pointer to the end of the newly allocated stack.
    pub fn allocate_stack(&mut self, size: usize) -> Option<VirtAddr> {
        // We assumed the stack is aligned earlier, so let's assert that.
        assert!(size & 0xf == 0x00, "stack alloc unaligned.");

        // Make sure the stack fits
        if self.cur_alloc.0.checked_add(size)? > self.memory.len() {
            return None;
        }

        let base = VirtAddr(self.memory.len() - size);

        // Mark the new memory as uninitialized and writable.
        let perms = match crate::ENABLE_RAW_PERM {
            false => Perm(PERM_READ | PERM_WRITE),
            true  => Perm(PERM_RAW | PERM_WRITE),
        };
        self.set_permissions(base, size, perms);

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

        // Mark dirty blocks
        let block_start = addr.0 / DIRTY_BLOCK_SIZE;
        let block_end   = (addr.0 + size) / DIRTY_BLOCK_SIZE;

        for block in block_start..=block_end {
            // Determine the bitmap position of the dirty block
            let idx = block / 64;
            let bit = block % 64;

            // Check if the block is not dirty
            if self.dirty_bitmap[idx] & (1 << bit) == 0 {
                // Block is not dirty yet, add it to the dirty list.
                self.dirty.push(block);

                // Update the dirty bitmap
                self.dirty_bitmap[idx] |= 1 << bit;
            }
        }

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
            let idx = block / 64;
            let bit = block % 64;

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
                .for_each(|x| {*x = Perm((x.0 | PERM_READ) & !PERM_RAW)});
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
            // Check if the requested perm contained EXEC, if so return a ExecFault Instead.
            if perm.0 & PERM_EXEC != 0 {
                return Err(VmExit::ExecFault(addr, buf.len()));
            }
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

