
const PERM_READ : u8 = 1 << 0;
const PERM_WRITE: u8 = 1 << 1;
const PERM_EXEC : u8 = 1 << 2;
// Read after write
const PERM_RAW  : u8 = 1 << 3;


/// Permission flags to track the state of bytes in memory.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct Perm(u8);

/// A guest virtual address
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct VirtAddr(usize);

/// The memory space for a single emu
struct Mmu {
    /// Block of memory for this address space
    /// Offset 0 will correspond to offset 0 in the guests address space.
    memory: Vec<u8>,

    /// Permission bytes for the corresponding byte in `memory`
    permissions: Vec<Perm>,

    /// Current base address of the next allocation to perform
    cur_alloc: VirtAddr,
}

impl Mmu {
    /// Create a new memory space of size `size`
    fn new(size: usize) -> Self {
        Mmu {
            memory     : vec![0; size],
            permissions: vec![Perm(0); size],
            cur_alloc  : VirtAddr(0x10000),
        }
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

struct Emulator {
    /// The memory belonging to this emu
    pub memory: Mmu    
}

impl Emulator {
    /// Create a new emulator with `size` bytes of memory
    fn new(size: usize) -> Self {
        Emulator {
            memory: Mmu::new(size),
        }
    }
}

fn main() {

    let mut emu = Emulator::new(1024*1024);

    let mut tmp = emu.memory.allocate(4096).unwrap();
    emu.memory.write_from(tmp, b"AAAABBBBCCCCDDDD").unwrap();

    let mut bytes = [0u8; 4];
    emu.memory.read_into(tmp, &mut bytes).unwrap();

    print!("{:x?} \n", bytes);
    println!("Hello, world!");
}
