use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::mmu::VirtAddr;

#[cfg(target_os="windows")]
pub fn alloc_rwx(size: usize) -> &'static mut [u8] {
    extern {
        fn VirtualAlloc(lpAddress: *const u8, dwSize: usize,
                        flAllocationType: u32, flProtect: u32) -> *mut u8;
    }

    unsafe {
        const PAGE_EXECUTE_READWRITE: u32 = 0x40;

        const MEM_COMMIT:  u32 = 0x00001000;
        const MEM_RESERVE: u32 = 0x00002000;

        let ret = VirtualAlloc(0 as *const _, size, MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
        assert!(!ret.is_null());

        std::slice::from_raw_parts_mut(ret, size)
    }
}

#[cfg(target_os="linux")]
pub fn alloc_rwx(size: usize) -> &'static mut [u8] {
    extern {
        fn mmap(addr: *mut u8, length: usize, prot: i32, flags: i32, fd: i32,
                offset: usize) -> *mut u8;
    }

    unsafe {
        // Alloc RWX and MAP_PRIVATE | MAP_ANON
        let ret = mmap(0 as *mut u8, size, 7, 34, -1, 0);
        assert!(!ret.is_null());
        
        std::slice::from_raw_parts_mut(ret, size)
    }
}


static JIT_SIZE: usize = 16 * 1024 * 1024;

pub struct JitCache {
    /// A big vector of blocks corresponding to guest binary virtual addresses.
    ///
    /// A zero block indicates that this addr has not been Jitted yet.
    blocks: Box<[AtomicUsize]>,

    /// The actual RWX chunk of memory that we can write our instruction to,
    /// along with the total number of bytes in use.
    backing_store: Mutex<(&'static mut [u8], usize)>,
}


// JIT Calling convention:
// r8  - Pointer to the base of mmu.memory.
// r9  - Pointer to the base of mmu.permissions.
// r10 - Pointer to the base of mmu.dirty.
// r11 - Pointer to the base of mmu.dirty_bitmap.
// r12 - Dirty index for the dirty list.
// r13 - Pointer to the emulators register vector.
// r14 - Pointer to the base of jitcache.blocks.
//
// RAX -> scratch, return code
// RBX -> can't be used to return values in inline asm, so we ignore it
// RCX -> scratch
// RDX -> scratch, return argument
//
// JIT Return code:
// RAX: 1 -> Branch resolution error (RDX is requested PC)
// RAX: 2 -> ECALL instruction was hit
// RAX: 3 -> EBREAK instruction was hit
// RAX: 4 -> Read fault    -> RDX = pc, RCX = address
// RAX: 5 -> Write fault   -> RDX = pc, RCX = address
// RAX: 6 -> ECALL was hit -> RDX = pc, RCX is the address to call to resume execution after the
//                            breakpoint has been handled.

impl JitCache {
    pub fn new(max_guest_address: VirtAddr) -> Self {

        // We're asuming that instructions are a fixed 4 byte, so we round up here.
        let aligned_max_address = (max_guest_address.0 + 3) / 4;

        JitCache {
            // Hacky way of creating a slice of AtomicUsizes
            blocks: (0..aligned_max_address).map(|_| {AtomicUsize::new(0)})
                .collect::<Vec<_>>().into_boxed_slice(),

            backing_store: Mutex::new((alloc_rwx(JIT_SIZE), 0)),
        }
    }

    /// Look up the relevant JIT Address for any given guest addr.
    pub fn lookup(&self, addr: VirtAddr) -> Option<usize> {
        assert!(addr.0 & 3 == 0, "Unaligned address in JIT lookup.");

        // If we've already jitted the requested block, return it's address.
        match self.blocks[addr.0 / 4].load(Ordering::SeqCst) {
            0 => None,
            x => Some(x),
        }
    }

    /// Getter function to get total number of blocks in the JIT
    pub fn num_blocks(&self) -> usize {
        self.blocks.len()
    }

    /// Get the address of the JIT block table
    pub fn translation_table(&self) -> usize {
        self.blocks.as_ptr() as usize
    }

    /// Update the JIT with a new block of code. Return the address of the newly
    /// added block.
    pub fn add_mapping(&self, addr: VirtAddr, code: &[u8]) -> usize {
        assert!(addr.0 & 3 == 0, "Unaligned address in JIT addition.");

        // Lock the backing store of the JIT for exclusive access.
        let mut backing_store = self.backing_store.lock().unwrap();

        // With the backing store locked, we can check in another thread already added a
        // mapping in the main time. If so, return here instead of re-jitting the same block.
        if let Some(existing) = self.lookup(addr) {
            return existing;
        }

        // Check whether we have enough space left in the JIT store.
        let jit_inuse     = backing_store.1;
        let jit_remaining = backing_store.0.len() - jit_inuse;
        assert!(code.len() < jit_remaining, "JIT ran out of space.");

        // Copy the new code into the JIT.
        backing_store.0[jit_inuse..jit_inuse + code.len()].copy_from_slice(code);

        // Get the address of the block we just jitted.
        let new_addr = backing_store.0[jit_inuse..].as_ptr() as usize;

        // Update the JIT Lookup table
        self.blocks[addr.0 / 4].store(new_addr, Ordering::SeqCst);

        // Update the number of bytes in use.
        backing_store.1 += code.len();

        // DEBUG; Print JIT additions
        //println!("Added JIT for {:#x} -> {:#x}", addr.0, new_addr);

        new_addr
    }
}
